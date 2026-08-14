from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from .models import Registry
from .probes import run_readonly
from .settings import discovery_roots, env_enabled

IGNORED_DIRS = {
    ".git",
    ".venv",
    ".npm",
    "venv",
    "node_modules",
    "__pycache__",
    ".cache",
    "dist",
    ".next",
    "build",
    "data",
    "backup",
    "backups",
    "exports",
}
PROJECT_MARKERS = {
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
    "app.py",
    "manage.py",
}


def fingerprint(kind: str, target: str) -> str:
    digest = hashlib.sha256(f"{kind}:{target}".encode()).hexdigest()
    return f"{kind}:{digest[:20]}"


def canonical_path(path: Path) -> Path:
    """Normalize aliases so WSL and symlinked roots do not create duplicates."""

    try:
        return path.expanduser().resolve(strict=False)
    except OSError:
        return path.expanduser().absolute()


def known_fingerprints(registry: Registry) -> set[str]:
    known: set[str] = set()
    for site in registry.sites:
        for url in site.urls:
            host = (urlparse(url.url).hostname or "").lower()
            if host:
                known.add(f"hostname:{host}")
        for component in site.components:
            known.add(f"{component.kind}:{component.target}")
        for path in site.source_paths:
            known.add(f"path:{canonical_path(Path(path))}")
    return known


def discover_projects(roots: list[Path], known: set[str]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    seen: set[Path] = set()
    known_paths = [
        canonical_path(Path(value[5:])) for value in known if value.startswith("path:")
    ]
    for root in roots:
        if not root.exists():
            continue
        root_depth = len(root.parts)
        for current, dirs, files in os.walk(root):
            path = Path(current)
            depth = len(path.parts) - root_depth
            dirs[:] = [
                item
                for item in dirs
                if item not in IGNORED_DIRS
                and not item.startswith("rollback_snapshot")
                and not item.startswith("backup_")
            ]
            if depth >= 4:
                dirs[:] = []
            markers = sorted(PROJECT_MARKERS.intersection(files))
            canonical = canonical_path(path)
            if not markers or canonical in seen:
                continue
            seen.add(canonical)
            if any(
                canonical == known_path or known_path in canonical.parents
                for known_path in known_paths
            ):
                continue
            target = str(path)
            candidates.append(
                {
                    "fingerprint": fingerprint("project", target),
                    "kind": "project",
                    "name": path.name,
                    "target": target,
                    "detail": {"markers": markers[:6]},
                }
            )
            if len(candidates) >= 150:
                return candidates
    return candidates


async def discover_systemd(known: set[str]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    unit_dirs = [
        (Path.home() / ".config/systemd/user", "systemd_user"),
        (Path("/etc/systemd/system"), "systemd_system"),
    ]
    for directory, kind in unit_dirs:
        if not directory.exists():
            continue
        for path in sorted(directory.glob("*.service")):
            key = f"{kind}:{path.name}"
            paired_timer = f"{kind}:{path.stem}.timer"
            if key in known or paired_timer in known:
                continue
            candidates.append(
                {
                    "fingerprint": fingerprint(kind, path.name),
                    "kind": kind,
                    "name": path.stem,
                    "target": path.name,
                    "detail": {"source": str(path)},
                }
            )
    return candidates


async def discover_docker(known: set[str]) -> list[dict[str, Any]]:
    code, output, _ = await run_readonly(
        ["docker", "ps", "--format", "{{json .}}"], timeout=8
    )
    if code != 0:
        return []
    candidates: list[dict[str, Any]] = []
    for line in output.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        name = str(row.get("Names", ""))
        if not name or f"docker:{name}" in known:
            continue
        candidates.append(
            {
                "fingerprint": fingerprint("docker", name),
                "kind": "docker",
                "name": name,
                "target": name,
                "detail": {
                    "image": str(row.get("Image", ""))[:160],
                    "ports": str(row.get("Ports", ""))[:240],
                },
            }
        )
    return candidates


def discover_cloudflare(known: set[str]) -> list[dict[str, Any]]:
    base = Path.home() / ".cloudflared"
    if not base.exists():
        return []
    candidates: list[dict[str, Any]] = []
    for path in sorted(list(base.glob("*.yml")) + list(base.glob("*.yaml"))):
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError):
            continue
        for ingress in raw.get("ingress", []) or []:
            host = str(ingress.get("hostname", "")).lower().strip()
            if not host or f"hostname:{host}" in known:
                continue
            candidates.append(
                {
                    "fingerprint": fingerprint("hostname", host),
                    "kind": "hostname",
                    "name": host,
                    "target": f"https://{host}",
                    "detail": {"config": path.name},
                }
            )
    return candidates


async def discover_all(
    registry: Registry,
    roots: list[Path] | None = None,
) -> list[dict[str, Any]]:
    if not (
        env_enabled("SITES_HUB_EXPOSE_INTERNALS")
        and env_enabled("SITES_HUB_DISCOVERY_ENABLED")
    ):
        return []
    roots = discovery_roots() if roots is None else roots
    if not roots:
        return []
    known = known_fingerprints(registry)
    systemd, docker, projects = await asyncio.gather(
        discover_systemd(known),
        discover_docker(known),
        asyncio.to_thread(discover_projects, roots, known),
    )
    cloudflare = await asyncio.to_thread(discover_cloudflare, known)
    unique: dict[str, dict[str, Any]] = {}
    for item in [*systemd, *docker, *cloudflare, *projects]:
        unique[item["fingerprint"]] = item
    return sorted(unique.values(), key=lambda item: (item["kind"], item["name"]))[:300]
