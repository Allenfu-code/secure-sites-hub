import os
import sqlite3
import stat
from datetime import UTC, datetime, timedelta

import pytest

from app.storage import HistoryStore, UnsafeStoragePath


def test_history_store_uses_private_permissions(tmp_path) -> None:
    store = HistoryStore(tmp_path / "data" / "history.sqlite3")
    if os.name == "posix":
        assert stat.S_IMODE(store.path.parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(store.path.stat().st_mode) == 0o600


def test_history_store_rejects_symlinked_parent(tmp_path) -> None:
    real_parent = tmp_path / "real-data"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked-data"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(UnsafeStoragePath, match="parent.*symlink"):
        HistoryStore(linked_parent / "history.sqlite3")


def test_history_store_rejects_symlinked_database_file(tmp_path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    outside = tmp_path / "outside.sqlite3"
    outside.write_bytes(b"")
    database = data_dir / "history.sqlite3"
    database.symlink_to(outside)

    with pytest.raises(UnsafeStoragePath, match="file.*symlink"):
        HistoryStore(database)


def test_history_store_fails_closed_when_chmod_fails(
    monkeypatch,
    tmp_path,
) -> None:
    def denied(*args, **kwargs):
        raise PermissionError("chmod denied")

    monkeypatch.setattr(os, "chmod", denied)

    with pytest.raises(PermissionError, match="chmod denied"):
        HistoryStore(tmp_path / "data" / "history.sqlite3")


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership check")
def test_history_store_rejects_wrong_owner(monkeypatch, tmp_path) -> None:
    actual_uid = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: actual_uid + 1)

    with pytest.raises(UnsafeStoragePath, match="not owned"):
        HistoryStore(tmp_path / "data" / "history.sqlite3")


def _record(
    store: HistoryStore,
    *,
    site_id: str,
    status: str,
    available: bool,
    checked_at: datetime,
) -> None:
    store.record_site(
        site_id=site_id,
        status=status,
        available=available,
        checked_at=checked_at.isoformat(),
        latency_ms=25,
        checks=[
            {
                "name": "Public URL",
                "check_type": "public_http",
                "target": "https://example.com",
                "status": status,
                "latency_ms": 25,
                "detail": "test",
            }
        ],
    )


def test_daily_history_returns_90_days_and_uses_worst_daily_status(
    tmp_path,
) -> None:
    store = HistoryStore(tmp_path / "history.sqlite3")
    now = datetime.now(UTC)
    _record(
        store,
        site_id="example",
        status="healthy",
        available=True,
        checked_at=now - timedelta(days=89),
    )
    _record(
        store,
        site_id="example",
        status="healthy",
        available=True,
        checked_at=now,
    )
    _record(
        store,
        site_id="example",
        status="degraded",
        available=False,
        checked_at=now + timedelta(microseconds=1),
    )
    _record(
        store,
        site_id="example",
        status="down",
        available=False,
        checked_at=now - timedelta(days=91),
    )

    history = store.daily_history("example", days=90)

    assert len(history) == 90
    assert history[0] == {
        "bucket": (now - timedelta(days=89)).date().isoformat(),
        "status": "healthy",
    }
    assert history[-1] == {
        "bucket": now.date().isoformat(),
        "status": "degraded",
    }
    assert (now - timedelta(days=91)).date().isoformat() not in {
        item["bucket"] for item in history
    }
    assert store.uptime("example", hours=24 * 90) == 66.67


def test_candidates_are_upserted_filtered_and_keep_first_seen(tmp_path) -> None:
    store = HistoryStore(tmp_path / "history.sqlite3")
    now = datetime.now(UTC)
    first_seen = (now - timedelta(hours=2)).isoformat()
    last_seen = now.isoformat()
    stale_seen = (now - timedelta(hours=25)).isoformat()
    candidate = {
        "fingerprint": "project:one",
        "kind": "project",
        "name": "First name",
        "target": "/srv/first",
        "detail": {"markers": ["pyproject.toml"]},
    }
    store.upsert_candidates([candidate], first_seen)
    store.upsert_candidates(
        [
            {
                **candidate,
                "name": "Updated name",
                "target": "/srv/updated",
                "detail": {"markers": ["package.json"]},
            }
        ],
        last_seen,
    )
    store.upsert_candidates(
        [
            {
                "fingerprint": "docker:stale",
                "kind": "docker",
                "name": "Stale",
                "target": "stale",
                "detail": {},
            }
        ],
        stale_seen,
    )

    candidates = store.candidates(max_age_hours=24)

    assert candidates == [
        {
            "fingerprint": "project:one",
            "kind": "project",
            "name": "Updated name",
            "target": "/srv/updated",
            "detail": {"markers": ["package.json"]},
            "first_seen_at": first_seen,
            "last_seen_at": last_seen,
        }
    ]


def test_sync_candidates_removes_items_missing_from_latest_scan(tmp_path) -> None:
    store = HistoryStore(tmp_path / "history.sqlite3")
    first_seen = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    last_seen = datetime.now(UTC).isoformat()
    kept = {
        "fingerprint": "project:kept",
        "kind": "project",
        "name": "Kept",
        "target": "/srv/kept",
        "detail": {},
    }
    removed = {
        "fingerprint": "project:removed",
        "kind": "project",
        "name": "Removed",
        "target": "/srv/removed",
        "detail": {},
    }
    store.sync_candidates([kept, removed], first_seen)

    store.sync_candidates([{**kept, "name": "Still kept"}], last_seen)

    assert store.candidates() == [
        {
            **kept,
            "name": "Still kept",
            "first_seen_at": first_seen,
            "last_seen_at": last_seen,
        }
    ]


def test_purge_removes_history_older_than_90_days_and_stale_candidates(
    tmp_path,
) -> None:
    database = tmp_path / "history.sqlite3"
    store = HistoryStore(database)
    now = datetime.now(UTC)
    _record(
        store,
        site_id="recent",
        status="healthy",
        available=True,
        checked_at=now - timedelta(days=89),
    )
    _record(
        store,
        site_id="old",
        status="down",
        available=False,
        checked_at=now - timedelta(days=91),
    )
    store.upsert_candidates(
        [
            {
                "fingerprint": "project:recent",
                "kind": "project",
                "name": "Recent",
                "target": "/srv/recent",
                "detail": {},
            }
        ],
        now.isoformat(),
    )
    store.upsert_candidates(
        [
            {
                "fingerprint": "project:old",
                "kind": "project",
                "name": "Old",
                "target": "/srv/old",
                "detail": {},
            }
        ],
        (now - timedelta(days=8)).isoformat(),
    )

    store.purge(retention_days=90)

    with sqlite3.connect(database) as connection:
        site_ids = {
            row[0] for row in connection.execute("SELECT site_id FROM site_snapshots")
        }
        check_site_ids = {
            row[0] for row in connection.execute("SELECT site_id FROM check_snapshots")
        }
        fingerprints = {
            row[0] for row in connection.execute("SELECT fingerprint FROM candidates")
        }
    assert site_ids == {"recent"}
    assert check_site_ids == {"recent"}
    assert fingerprints == {"project:recent"}
