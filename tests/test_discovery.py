from pathlib import Path

from app import discovery
from app.discovery import canonical_path, discover_projects
from app.models import Registry
from app.settings import discovery_roots


def _project(path: Path) -> Path:
    path.mkdir(parents=True)
    (path / "package.json").write_text("{}", encoding="utf-8")
    return path


def test_discovery_ignores_caches_exports_and_known_descendants(tmp_path) -> None:
    known = _project(tmp_path / "known")
    _project(known / "server")
    _project(tmp_path / ".npm" / "_npx" / "cache-entry")
    _project(tmp_path / "exports" / "snapshot")
    fresh = _project(tmp_path / "fresh-project")

    candidates = discover_projects([tmp_path], {f"path:{canonical_path(known)}"})

    assert [item["target"] for item in candidates] == [str(fresh)]


def test_discovery_deduplicates_symlinked_roots(tmp_path) -> None:
    real_root = tmp_path / "real"
    project = _project(real_root / "project")
    alias = tmp_path / "alias"
    alias.symlink_to(real_root, target_is_directory=True)

    candidates = discover_projects([real_root, alias], set())

    assert len(candidates) == 1
    assert canonical_path(Path(candidates[0]["target"])) == canonical_path(project)


def test_discovery_roots_have_no_implicit_host_paths(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("SITES_HUB_DISCOVERY_ROOTS", raising=False)
    assert discovery_roots() == []

    first = tmp_path / "first"
    second = tmp_path / "second"
    monkeypatch.setenv(
        "SITES_HUB_DISCOVERY_ROOTS",
        f"{first}:{second}:{first}",
    )

    assert discovery_roots() == [first, second]


async def test_discover_all_without_roots_performs_no_host_discovery(
    monkeypatch,
) -> None:
    async def unexpected(*args, **kwargs):
        raise AssertionError("host discovery must remain disabled")

    monkeypatch.setattr(discovery, "discover_systemd", unexpected)
    monkeypatch.setattr(discovery, "discover_docker", unexpected)
    monkeypatch.setattr(discovery, "discover_cloudflare", unexpected)

    result = await discovery.discover_all(Registry(sites=[]), roots=[])

    assert result == []
