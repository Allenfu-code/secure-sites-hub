from __future__ import annotations

import json
import os
import sqlite3
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import RLock
from typing import Any


class UnsafeStoragePath(RuntimeError):
    """Raised when private history storage cannot be secured."""


class HistoryStore:
    def __init__(self, path: Path):
        self.path = path
        self._tighten_permissions()
        self._lock = RLock()
        self.initialize()

    @staticmethod
    def _lstat(path: Path):
        try:
            return os.lstat(path)
        except FileNotFoundError:
            return None

    def _reject_symlink_ancestors(self) -> None:
        current = self.path.parent.absolute()
        for candidate in (current, *current.parents):
            metadata = self._lstat(candidate)
            if metadata is not None and stat.S_ISLNK(metadata.st_mode):
                raise UnsafeStoragePath(
                    f"history database parent must not be a symlink: {candidate}"
                )

    def _secure_parent(self) -> None:
        self._reject_symlink_ancestors()
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = self._lstat(self.path.parent)
        if metadata is None or not stat.S_ISDIR(metadata.st_mode):
            raise UnsafeStoragePath("history database parent is not a directory")
        if os.name == "posix":
            if metadata.st_uid != os.geteuid():
                raise UnsafeStoragePath(
                    "history database parent is not owned by this process user"
                )
            os.chmod(self.path.parent, 0o700)
            metadata = os.lstat(self.path.parent)
            if stat.S_ISLNK(metadata.st_mode):
                raise UnsafeStoragePath("history database parent became a symlink")
            if stat.S_IMODE(metadata.st_mode) != 0o700:
                raise UnsafeStoragePath(
                    "history database parent permissions are not 0700"
                )

    def _secure_file(self, path: Path, *, create: bool) -> None:
        metadata = self._lstat(path)
        if metadata is None and create:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(path, flags, 0o600)
            except FileExistsError:
                pass
            else:
                os.close(descriptor)
            metadata = self._lstat(path)
        if metadata is None:
            return
        if stat.S_ISLNK(metadata.st_mode):
            raise UnsafeStoragePath(
                f"history database file must not be a symlink: {path.name}"
            )
        if not stat.S_ISREG(metadata.st_mode):
            raise UnsafeStoragePath(
                f"history database path is not a regular file: {path.name}"
            )
        if metadata.st_nlink != 1:
            raise UnsafeStoragePath(
                f"history database file must have one link: {path.name}"
            )
        if os.name == "posix":
            if metadata.st_uid != os.geteuid():
                raise UnsafeStoragePath(
                    f"history database file has the wrong owner: {path.name}"
                )
            os.chmod(path, 0o600)
            metadata = os.lstat(path)
            if stat.S_ISLNK(metadata.st_mode):
                raise UnsafeStoragePath(
                    f"history database file became a symlink: {path.name}"
                )
            if stat.S_IMODE(metadata.st_mode) != 0o600:
                raise UnsafeStoragePath(
                    f"history database permissions are not 0600: {path.name}"
                )

    def _tighten_permissions(self) -> None:
        self._secure_parent()
        self._secure_file(self.path, create=True)
        for path in (
            self.path.with_name(f"{self.path.name}-wal"),
            self.path.with_name(f"{self.path.name}-shm"),
        ):
            self._secure_file(path, create=False)

    def _connect(self) -> sqlite3.Connection:
        self._tighten_permissions()
        connection = sqlite3.connect(self.path, timeout=10)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA busy_timeout=5000")
            self._tighten_permissions()
            return connection
        except Exception:
            connection.close()
            raise

    def initialize(self) -> None:
        with self._lock, self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS site_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    site_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    available INTEGER NOT NULL,
                    latency_ms INTEGER,
                    checked_at TEXT NOT NULL,
                    detail_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS idx_site_snapshots_site_time
                    ON site_snapshots(site_id, checked_at);

                CREATE TABLE IF NOT EXISTS check_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    site_id TEXT NOT NULL,
                    check_name TEXT NOT NULL,
                    check_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    status TEXT NOT NULL,
                    latency_ms INTEGER,
                    checked_at TEXT NOT NULL,
                    detail TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_check_snapshots_site_time
                    ON check_snapshots(site_id, checked_at);

                CREATE TABLE IF NOT EXISTS candidates (
                    fingerprint TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    name TEXT NOT NULL,
                    target TEXT NOT NULL,
                    detail_json TEXT NOT NULL DEFAULT '{}',
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL
                );
                """
            )

    def record_site(
        self,
        site_id: str,
        status: str,
        available: bool,
        checked_at: str,
        latency_ms: int | None,
        checks: list[dict[str, Any]],
    ) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO site_snapshots
                    (site_id, status, available, latency_ms, checked_at, detail_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    site_id,
                    status,
                    int(available),
                    latency_ms,
                    checked_at,
                    json.dumps({"checks": len(checks)}, ensure_ascii=False),
                ),
            )
            connection.executemany(
                """
                INSERT INTO check_snapshots
                    (site_id, check_name, check_type, target, status,
                     latency_ms, checked_at, detail)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        site_id,
                        check["name"],
                        check.get("check_type", ""),
                        check["target"],
                        check["status"],
                        check.get("latency_ms"),
                        checked_at,
                        check.get("detail", "")[:500],
                    )
                    for check in checks
                ],
            )

    def uptime(self, site_id: str, hours: int) -> float | None:
        cutoff = (datetime.now(UTC) - timedelta(hours=hours)).isoformat()
        with self._lock, self._connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS total, SUM(available) AS available
                FROM site_snapshots
                WHERE site_id = ? AND checked_at >= ?
                """,
                (site_id, cutoff),
            ).fetchone()
        if not row or not row["total"]:
            return None
        return round((row["available"] or 0) * 100.0 / row["total"], 2)

    def daily_history(self, site_id: str, days: int = 90) -> list[dict[str, str]]:
        cutoff_date = (datetime.now(UTC) - timedelta(days=days - 1)).date()
        severity = {"unknown": 0, "healthy": 1, "degraded": 2, "down": 3}
        by_day: dict[str, str] = {}
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                """
                SELECT substr(checked_at, 1, 10) AS day, status
                FROM site_snapshots
                WHERE site_id = ? AND checked_at >= ?
                ORDER BY checked_at
                """,
                (site_id, cutoff_date.isoformat()),
            ).fetchall()
        for row in rows:
            current = by_day.get(row["day"], "unknown")
            if severity.get(row["status"], 0) >= severity.get(current, 0):
                by_day[row["day"]] = row["status"]
        result: list[dict[str, str]] = []
        for offset in range(days):
            day = cutoff_date + timedelta(days=offset)
            key = day.isoformat()
            result.append({"bucket": key, "status": by_day.get(key, "unknown")})
        return result

    def upsert_candidates(self, candidates: list[dict[str, Any]], seen_at: str) -> None:
        with self._lock, self._connect() as connection:
            connection.executemany(
                """
                INSERT INTO candidates
                    (fingerprint, kind, name, target, detail_json,
                     first_seen_at, last_seen_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    kind = excluded.kind,
                    name = excluded.name,
                    target = excluded.target,
                    detail_json = excluded.detail_json,
                    last_seen_at = excluded.last_seen_at
                """,
                [
                    (
                        item["fingerprint"],
                        item["kind"],
                        item["name"],
                        item["target"],
                        json.dumps(item.get("detail", {}), ensure_ascii=False),
                        seen_at,
                        seen_at,
                    )
                    for item in candidates
                ],
            )

    def sync_candidates(self, candidates: list[dict[str, Any]], seen_at: str) -> None:
        """Replace the discovery snapshot while preserving first-seen timestamps."""

        fingerprints = [item["fingerprint"] for item in candidates]
        with self._lock, self._connect() as connection:
            if fingerprints:
                placeholders = ",".join("?" for _ in fingerprints)
                connection.execute(
                    f"DELETE FROM candidates WHERE fingerprint NOT IN ({placeholders})",
                    fingerprints,
                )
            else:
                connection.execute("DELETE FROM candidates")
            connection.executemany(
                """
                INSERT INTO candidates
                    (fingerprint, kind, name, target, detail_json,
                     first_seen_at, last_seen_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    kind = excluded.kind,
                    name = excluded.name,
                    target = excluded.target,
                    detail_json = excluded.detail_json,
                    last_seen_at = excluded.last_seen_at
                """,
                [
                    (
                        item["fingerprint"],
                        item["kind"],
                        item["name"],
                        item["target"],
                        json.dumps(item.get("detail", {}), ensure_ascii=False),
                        seen_at,
                        seen_at,
                    )
                    for item in candidates
                ],
            )

    def candidates(self, max_age_hours: int = 24) -> list[dict[str, Any]]:
        cutoff = (datetime.now(UTC) - timedelta(hours=max_age_hours)).isoformat()
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                """
                SELECT fingerprint, kind, name, target, detail_json,
                       first_seen_at, last_seen_at
                FROM candidates
                WHERE last_seen_at >= ?
                ORDER BY kind, name
                """,
                (cutoff,),
            ).fetchall()
        return [
            {
                "fingerprint": row["fingerprint"],
                "kind": row["kind"],
                "name": row["name"],
                "target": row["target"],
                "detail": json.loads(row["detail_json"]),
                "first_seen_at": row["first_seen_at"],
                "last_seen_at": row["last_seen_at"],
            }
            for row in rows
        ]

    def purge(self, retention_days: int = 90) -> None:
        cutoff = (datetime.now(UTC) - timedelta(days=retention_days)).isoformat()
        stale_candidates = (datetime.now(UTC) - timedelta(days=7)).isoformat()
        with self._lock, self._connect() as connection:
            connection.execute(
                "DELETE FROM site_snapshots WHERE checked_at < ?", (cutoff,)
            )
            connection.execute(
                "DELETE FROM check_snapshots WHERE checked_at < ?", (cutoff,)
            )
            connection.execute(
                "DELETE FROM candidates WHERE last_seen_at < ?", (stale_candidates,)
            )
            connection.execute("PRAGMA optimize")
