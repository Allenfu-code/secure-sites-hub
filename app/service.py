from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any

from .discovery import discover_all
from .models import (
    CheckResult,
    ComponentView,
    SiteSpec,
    SiteView,
    utc_now_iso,
)
from .probes import (
    STATUS_LABELS,
    collect_windows_listeners,
    probe_component,
    probe_http,
)
from .registry import RegistryStore
from .settings import discovery_roots, env_enabled
from .storage import HistoryStore

CATEGORY_LABELS = {
    "public": "公開網站",
    "protected": "登入保護網站",
    "internal": "內部工具",
    "api": "API／Webhook",
    "infrastructure": "代理與基礎元件",
    "archived": "未部署／已封存",
}


class SitesHubService:
    def __init__(
        self,
        registry_path: Path,
        database_path: Path,
        windows_probe_script: Path,
    ):
        self.registry = RegistryStore(registry_path)
        self.history = HistoryStore(database_path)
        self.windows_probe_script = windows_probe_script
        self.current: dict[str, SiteView] = {}
        self._public_results: dict[tuple[str, str], CheckResult] = {}
        self._task: asyncio.Task | None = None
        self._stopping = asyncio.Event()
        self._last_public = 0.0
        self._last_discovery = 0.0
        self._last_purge = 0.0
        self._cycle_lock = asyncio.Lock()
        self.local_interval = int(os.getenv("LOCAL_CHECK_INTERVAL", "60"))
        self.public_interval = int(os.getenv("PUBLIC_CHECK_INTERVAL", "300"))
        self.discovery_interval = int(os.getenv("DISCOVERY_INTERVAL", "900"))
        self.expose_internals = env_enabled("SITES_HUB_EXPOSE_INTERNALS")
        self.discovery_roots = discovery_roots()
        self.discovery_enabled = (
            self.expose_internals
            and env_enabled("SITES_HUB_DISCOVERY_ENABLED")
            and bool(self.discovery_roots)
        )
        # Internal host probes require a second, deliberate opt-in. Merely
        # publishing the dashboard must never run host inspection commands.
        self.internal_probes_enabled = self.expose_internals and env_enabled(
            "SITES_HUB_PROBES_ENABLED"
        )

    @property
    def candidates_exposed(self) -> bool:
        """Candidates require both discovery and internal-data opt-ins."""

        return self.discovery_enabled and self.expose_internals

    async def start(self) -> None:
        await self.run_cycle(
            force_public=True,
            force_discovery=self.discovery_enabled,
        )
        self._task = asyncio.create_task(self._loop(), name="sites-hub-monitor")

    async def stop(self) -> None:
        self._stopping.set()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _loop(self) -> None:
        while not self._stopping.is_set():
            try:
                await asyncio.sleep(self.local_interval)
                await self.run_cycle()
            except asyncio.CancelledError:
                raise
            except Exception:
                # A failed collector must not take down the read-only dashboard.
                await asyncio.sleep(min(self.local_interval, 30))

    async def run_cycle(
        self,
        force_public: bool = False,
        force_discovery: bool = False,
    ) -> None:
        async with self._cycle_lock:
            loop = asyncio.get_running_loop()
            now = loop.time()
            include_public = force_public or (
                now - self._last_public >= self.public_interval
            )
            include_discovery = self.discovery_enabled and (
                force_discovery or now - self._last_discovery >= self.discovery_interval
            )
            registry = self.registry.load()

            windows_listeners: dict[int, list[dict]] = {}
            if self.internal_probes_enabled:
                windows_ports = [
                    int(component.target)
                    for site in registry.sites
                    for component in site.components
                    if component.kind == "windows_port" and component.target.isdigit()
                ]
                windows_listeners = await collect_windows_listeners(
                    windows_ports, self.windows_probe_script
                )

            component_jobs: dict[str, list[asyncio.Task[CheckResult]]] = {}
            for site in registry.sites:
                if self.internal_probes_enabled:
                    component_jobs[site.id] = [
                        asyncio.create_task(
                            probe_component(component, windows_listeners)
                        )
                        for component in site.components
                    ]
                else:
                    component_jobs[site.id] = [
                        asyncio.create_task(self._disabled_component_result(component))
                        for component in site.components
                    ]

            if include_public:
                url_jobs: dict[tuple[str, str], asyncio.Task[CheckResult]] = {}
                for site in registry.sites:
                    for url in site.urls:
                        url_jobs[(site.id, url.url)] = asyncio.create_task(
                            probe_http(url)
                        )
                for key, job in url_jobs.items():
                    self._public_results[key] = await job
                self._last_public = now

            generated_at = utc_now_iso()
            updated: dict[str, SiteView] = {}
            for site in registry.sites:
                component_results = [await task for task in component_jobs[site.id]]
                public_results = [
                    self._public_results.get((site.id, url.url))
                    or CheckResult(
                        name=url.label,
                        target=url.url,
                        status="unknown",
                        status_label=STATUS_LABELS["unknown"],
                        detail="等待第一次公開檢查",
                        required=url.required,
                        check_type="public_http",
                    )
                    for url in site.urls
                ]
                checks = [*public_results, *component_results]
                view = self._make_site_view(site, checks, generated_at)
                updated[site.id] = view
                if include_public and site.lifecycle != "archived":
                    latencies = [
                        item.latency_ms
                        for item in public_results
                        if item.latency_ms is not None
                    ]
                    available = (
                        any(item.status == "healthy" for item in public_results)
                        if public_results
                        else view.status in {"healthy", "degraded"}
                    )
                    self.history.record_site(
                        site.id,
                        view.status,
                        available,
                        generated_at,
                        round(sum(latencies) / len(latencies)) if latencies else None,
                        [item.model_dump() for item in checks],
                    )
            self.current = updated

            if include_discovery:
                candidates = await discover_all(
                    registry,
                    roots=self.discovery_roots,
                )
                self.history.sync_candidates(candidates, generated_at)
                self._last_discovery = now
            if now - self._last_purge >= 86_400:
                self.history.purge(90)
                self._last_purge = now

    async def _disabled_component_result(self, component) -> CheckResult:
        """Return a synthetic result without touching the host environment."""

        target = component.target
        if component.kind == "windows_port":
            target = f"Windows :{component.target}"
        elif component.kind == "wsl_port":
            target = f"127.0.0.1:{component.target}"
        return CheckResult(
            name=component.name,
            target=target,
            status="unknown",
            status_label=STATUS_LABELS["unknown"],
            detail="內部探測已停用",
            required=component.required,
            check_type=component.kind,
        )

    def _make_site_view(
        self, site: SiteSpec, checks: list[CheckResult], checked_at: str
    ) -> SiteView:
        status = aggregate_status(site, checks)
        component_by_target = {
            result.target: result
            for result in checks
            if result.check_type != "public_http"
        }
        components: list[ComponentView] = []
        for component in site.components:
            lookup_target = component.target
            if component.kind == "windows_port":
                lookup_target = f"Windows :{component.target}"
            elif component.kind == "wsl_port":
                lookup_target = f"127.0.0.1:{component.target}"
            result = component_by_target.get(lookup_target)
            components.append(
                ComponentView(
                    id=component.id,
                    name=component.name,
                    platform=component.platform,
                    kind=component.kind,
                    target=component.target,
                    status=result.status if result else "unknown",
                    status_label=(
                        result.status_label if result else STATUS_LABELS["unknown"]
                    ),
                    detail=result.detail if result else "尚未檢查",
                    required=component.required,
                )
            )
        return SiteView(
            id=site.id,
            name=site.name,
            description=site.description,
            category=site.category,
            category_label=CATEGORY_LABELS[site.category],
            lifecycle=site.lifecycle,
            status=status,
            status_label=STATUS_LABELS[status],
            visibility=site.visibility,
            urls=[url.model_dump() for url in site.urls],
            source_paths=site.source_paths,
            dependencies=site.dependencies,
            components=components,
            checks=checks,
            last_checked_at=checked_at,
            uptime_24h=self.history.uptime(site.id, 24),
            uptime_90d=self.history.uptime(site.id, 24 * 90),
            notes=site.notes,
        )

    def _serialize_site(self, item: SiteView) -> dict[str, Any]:
        if self.expose_internals:
            return item.model_dump()
        # This is intentionally an allowlist rather than a blacklist. New
        # internal model fields therefore remain private by default.
        return {
            "id": item.id,
            "name": item.name,
            "description": item.description,
            "category": item.category,
            "category_label": item.category_label,
            "lifecycle": item.lifecycle,
            "status": item.status,
            "status_label": item.status_label,
            "visibility": item.visibility,
            "urls": [
                {"url": url["url"], "label": url.get("label", "開啟網站")}
                for url in item.urls
            ],
            "components": [
                {
                    "id": component.id,
                    "name": component.name,
                    "platform": component.platform,
                    "kind": component.kind,
                    "status": component.status,
                    "status_label": component.status_label,
                    "required": component.required,
                }
                for component in item.components
            ],
            "checks": [
                {
                    "name": check.name,
                    "status": check.status,
                    "status_label": check.status_label,
                    "checked_at": check.checked_at,
                    "latency_ms": check.latency_ms,
                    "required": check.required,
                    "check_type": check.check_type,
                }
                for check in item.checks
            ],
            "last_checked_at": item.last_checked_at,
            "uptime_24h": item.uptime_24h,
            "uptime_90d": item.uptime_90d,
        }

    def sites(self) -> list[dict[str, Any]]:
        return [
            self._serialize_site(item)
            for item in sorted(
                self.current.values(),
                key=lambda item: (
                    list(CATEGORY_LABELS).index(item.category),
                    item.name,
                ),
            )
        ]

    def site(self, site_id: str) -> dict[str, Any] | None:
        item = self.current.get(site_id)
        return self._serialize_site(item) if item else None

    def summary(self) -> dict[str, int]:
        active = [
            site for site in self.current.values() if site.lifecycle != "archived"
        ]
        result = {
            "total": len(self.current),
            "healthy": sum(site.status == "healthy" for site in active),
            "degraded": sum(site.status == "degraded" for site in active),
            "down": sum(site.status == "down" for site in active),
            "unknown": sum(site.status == "unknown" for site in active),
            "archived": sum(
                site.lifecycle == "archived" for site in self.current.values()
            ),
        }
        if self.candidates_exposed:
            result["candidates"] = len(self.history.candidates())
        return result

    def candidates(self) -> list[dict[str, Any]]:
        if not self.candidates_exposed:
            return []
        return self.history.candidates()

    def categories(self) -> list[dict[str, Any]]:
        sites = list(self.current.values())
        return [
            {
                "value": key,
                "label": label,
                "count": sum(site.category == key for site in sites),
            }
            for key, label in CATEGORY_LABELS.items()
            if any(site.category == key for site in sites)
        ]


def aggregate_status(site: SiteSpec, checks: list[CheckResult]) -> str:
    if site.lifecycle == "archived":
        return "unknown"
    required = [check for check in checks if check.required]
    if not required:
        return "unknown"
    public = [check for check in required if check.check_type == "public_http"]
    components = [check for check in required if check.check_type != "public_http"]
    if public:
        public_healthy = any(check.status == "healthy" for check in public)
        if all(check.status == "down" for check in public):
            return "down"
        if not public_healthy:
            return (
                "unknown"
                if all(check.status == "unknown" for check in public)
                else "down"
            )
        if any(check.status != "healthy" for check in public):
            return "degraded"
        if any(check.status != "healthy" for check in components):
            return "degraded"
        return "healthy"

    if components and all(check.status == "healthy" for check in components):
        return "healthy"
    if any(check.status == "healthy" for check in components):
        return "degraded"
    if components and all(check.status == "down" for check in components):
        return "down"
    return "unknown"
