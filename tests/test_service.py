from pathlib import Path

import pytest

from app import service as service_module
from app.models import CheckResult, SiteSpec
from app.service import SitesHubService, aggregate_status

ROOT = Path(__file__).resolve().parents[1]


def _site(*, lifecycle: str = "production") -> SiteSpec:
    return SiteSpec(
        id="example",
        name="Example",
        category="public" if lifecycle != "archived" else "archived",
        lifecycle=lifecycle,
        visibility="public",
    )


def _check(
    status: str,
    *,
    check_type: str,
    required: bool = True,
) -> CheckResult:
    return CheckResult(
        name=check_type,
        target=f"target:{check_type}",
        status=status,
        status_label=status,
        required=required,
        check_type=check_type,
    )


@pytest.mark.parametrize(
    ("site", "checks", "expected"),
    [
        (
            _site(),
            [
                _check("healthy", check_type="public_http"),
                _check("healthy", check_type="systemd_user"),
            ],
            "healthy",
        ),
        (
            _site(),
            [
                _check("healthy", check_type="public_http"),
                _check("down", check_type="systemd_user"),
            ],
            "degraded",
        ),
        (
            _site(),
            [
                _check("down", check_type="public_http"),
                _check("healthy", check_type="systemd_user"),
            ],
            "down",
        ),
        (
            _site(lifecycle="archived"),
            [_check("healthy", check_type="public_http")],
            "unknown",
        ),
    ],
    ids=["healthy", "degraded", "down", "archived"],
)
def test_aggregate_status(
    site: SiteSpec,
    checks: list[CheckResult],
    expected: str,
) -> None:
    assert aggregate_status(site, checks) == expected


def test_aggregate_status_ignores_optional_failures() -> None:
    checks = [
        _check("healthy", check_type="public_http"),
        _check("down", check_type="systemd_user", required=False),
    ]

    assert aggregate_status(_site(), checks) == "healthy"


async def test_public_mode_runs_only_public_http_and_synthetic_checks(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.delenv("SITES_HUB_EXPOSE_INTERNALS", raising=False)
    monkeypatch.delenv("SITES_HUB_DISCOVERY_ROOTS", raising=False)
    monkeypatch.setenv("SITES_HUB_DISCOVERY_ENABLED", "true")
    monkeypatch.setenv("SITES_HUB_PROBES_ENABLED", "true")

    async def unexpected(*args, **kwargs):
        raise AssertionError("public mode must not inspect the host")

    async def fake_probe_http(url_spec):
        return CheckResult(
            name=url_spec.label,
            target=url_spec.url,
            status="healthy",
            status_label="正常",
            detail="HTTP 200",
            required=url_spec.required,
            check_type="public_http",
        )

    monkeypatch.setattr(service_module, "collect_windows_listeners", unexpected)
    monkeypatch.setattr(service_module, "probe_component", unexpected)
    monkeypatch.setattr(service_module, "discover_all", unexpected)
    monkeypatch.setattr(service_module, "probe_http", fake_probe_http)

    service = SitesHubService(
        registry_path=ROOT / "sites.example.yaml",
        database_path=tmp_path / "data" / "history.sqlite3",
        windows_probe_script=tmp_path / "windows_probe.ps1",
    )

    await service.run_cycle(force_public=True, force_discovery=True)

    assert service.discovery_enabled is False
    assert service.internal_probes_enabled is False
    storefront = service.current["example-storefront"]
    assert storefront.checks[0].status == "healthy"
    assert storefront.components[0].status == "unknown"


def test_discovery_requires_internal_exposure_and_explicit_roots(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("SITES_HUB_DISCOVERY_ENABLED", "true")
    monkeypatch.setenv("SITES_HUB_DISCOVERY_ROOTS", str(tmp_path / "projects"))
    monkeypatch.delenv("SITES_HUB_EXPOSE_INTERNALS", raising=False)

    public_service = SitesHubService(
        registry_path=ROOT / "sites.example.yaml",
        database_path=tmp_path / "public" / "history.sqlite3",
        windows_probe_script=tmp_path / "windows_probe.ps1",
    )
    assert public_service.discovery_enabled is False
    assert public_service.candidates_exposed is False

    monkeypatch.setenv("SITES_HUB_EXPOSE_INTERNALS", "true")
    internal_service = SitesHubService(
        registry_path=ROOT / "sites.example.yaml",
        database_path=tmp_path / "internal" / "history.sqlite3",
        windows_probe_script=tmp_path / "windows_probe.ps1",
    )
    assert internal_service.discovery_enabled is True
    assert internal_service.candidates_exposed is True
