from __future__ import annotations

from pathlib import Path
from threading import RLock

import yaml

from .models import Registry


class RegistryStore:
    """Reloads the human-reviewed YAML registry when its mtime changes."""

    def __init__(self, path: Path):
        self.path = path
        self._lock = RLock()
        self._mtime_ns: int | None = None
        self._registry: Registry | None = None

    def load(self, force: bool = False) -> Registry:
        with self._lock:
            stat = self.path.stat()
            if (
                not force
                and self._registry is not None
                and self._mtime_ns == stat.st_mtime_ns
            ):
                return self._registry
            raw = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
            registry = Registry.model_validate(raw)
            self._registry = registry
            self._mtime_ns = stat.st_mtime_ns
            return registry
