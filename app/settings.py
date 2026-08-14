from __future__ import annotations

import os
from pathlib import Path

TRUE_VALUES = frozenset({"1", "true", "yes", "on"})


def env_enabled(name: str) -> bool:
    """Return true only for an explicit, recognizable opt-in value."""

    return os.getenv(name, "").strip().lower() in TRUE_VALUES


def discovery_roots() -> list[Path]:
    """Read discovery roots from the environment without implicit host paths."""

    raw = os.getenv("SITES_HUB_DISCOVERY_ROOTS", "")
    roots: list[Path] = []
    seen: set[Path] = set()
    for value in raw.split(os.pathsep):
        value = value.strip()
        if not value:
            continue
        path = Path(value).expanduser()
        if path in seen:
            continue
        seen.add(path)
        roots.append(path)
    return roots
