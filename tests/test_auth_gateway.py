import os
import re
import sqlite3
import stat
import subprocess
import sys
from collections import deque
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from app import auth_gateway
from app.private_files import PrivateFileError

ROOT = Path(__file__).resolve().parents[1]
TEST_PASSWORD = "correct horse battery staple"


def create_account_database(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE admin_account "
            "(username TEXT, password_hash TEXT, session_version INTEGER)"
        )
        connection.execute(
            "INSERT INTO admin_account VALUES (?, ?, ?)",
            (
                "operator",
                auth_gateway.PASSWORD_HASHER.hash(TEST_PASSWORD),
                7,
            ),
        )


def gateway_settings(
    tmp_path: Path,
    database_path: Path,
) -> auth_gateway.GatewaySettings:
    return auth_gateway.GatewaySettings(
        database_path=database_path,
        secret_path=tmp_path / "private" / ".session-secret",
        cache_path=tmp_path / "private" / ".auth-cache.json",
        upstream="http://127.0.0.1:9620",
        public_host="sites.example.com",
    )


@pytest.fixture()
def gateway(tmp_path):
    database_path = tmp_path / "accounts.sqlite3"
    create_account_database(database_path)
    settings = gateway_settings(tmp_path, database_path)
    application = auth_gateway.create_app(settings)

    with TestClient(
        application,
        base_url="https://sites.test",
        client=("127.0.0.1", 50000),
    ) as client:
        yield client, database_path, tmp_path, settings, application.state.gateway


def csrf(client: TestClient, *, next_path: str = "/") -> str:
    response = client.get(f"/login?next={next_path}")
    assert response.status_code == 200
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', response.text)
    assert match is not None
    return match.group(1)


def log_in(client: TestClient, *, next_path: str = "/"):
    return client.post(
        f"/login?next={next_path}",
        data={
            "csrf_token": csrf(client, next_path=next_path),
            "username": "operator",
            "password": TEST_PASSWORD,
        },
        follow_redirects=False,
    )


def test_module_import_does_not_read_or_create_session_secret(tmp_path) -> None:
    secret_path = tmp_path / "import-runtime" / ".session-secret"
    environment = os.environ.copy()
    environment["SITES_HUB_SESSION_SECRET_FILE"] = str(secret_path)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from app import auth_gateway; assert not hasattr(auth_gateway, 'app')",
        ],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert not secret_path.parent.exists()


def test_environment_defaults_are_generic_and_do_not_touch_disk(
    monkeypatch,
) -> None:
    for name in (
        "SITES_HUB_AUTH_DB",
        "SITES_HUB_SESSION_SECRET_FILE",
        "SITES_HUB_AUTH_CACHE_FILE",
        "SITES_HUB_UPSTREAM",
        "SITES_HUB_PUBLIC_HOST",
        "SITES_HUB_AUTH_DB_IMMUTABLE",
    ):
        monkeypatch.delenv(name, raising=False)

    settings = auth_gateway.GatewaySettings.from_env()

    assert settings.public_host == "sites.example.com"
    assert settings.database_path == ROOT / "runtime" / "accounts.sqlite3"
    assert settings.secret_path == ROOT / "runtime" / ".session-secret"
    assert settings.cache_path == ROOT / "runtime" / ".auth-cache.json"
    assert settings.database_immutable is False
    assert settings.upstream == "http://127.0.0.1:9620"


@pytest.mark.parametrize(
    "upstream",
    [
        "https://example.com:443",
        "http://localhost:9620",
        "http://127.0.0.1",
        "http://user:password@127.0.0.1:9620",
        "http://127.0.0.1:9620/private",
    ],
)
def test_gateway_rejects_non_loopback_or_ambiguous_upstreams(
    tmp_path,
    upstream,
) -> None:
    with pytest.raises(ValueError, match="loopback"):
        auth_gateway.GatewaySettings(
            database_path=tmp_path / "accounts.sqlite3",
            secret_path=tmp_path / "private" / "secret",
            cache_path=tmp_path / "private" / "cache.json",
            upstream=upstream,
            public_host="sites.example.com",
        )


def test_environment_can_opt_in_to_immutable_database(monkeypatch) -> None:
    monkeypatch.setenv("SITES_HUB_AUTH_DB_IMMUTABLE", "true")

    assert auth_gateway.GatewaySettings.from_env().database_immutable is True


def test_database_connection_is_read_only_by_default(tmp_path) -> None:
    database_path = tmp_path / "accounts.sqlite3"
    create_account_database(database_path)

    with auth_gateway.database_connection(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM admin_account").fetchone() == (
            1,
        )
        with pytest.raises(sqlite3.OperationalError):
            connection.execute("DELETE FROM admin_account")


def test_database_connection_only_uses_immutable_when_requested(
    monkeypatch,
    tmp_path,
) -> None:
    calls: list[str] = []

    def fake_connect(database: str, *, uri: bool):
        assert uri is True
        calls.append(database)
        return object()

    monkeypatch.setattr(auth_gateway.sqlite3, "connect", fake_connect)

    auth_gateway.database_connection(tmp_path / "accounts.sqlite3")
    auth_gateway.database_connection(
        tmp_path / "accounts.sqlite3",
        immutable=True,
    )

    assert calls[0].endswith("?mode=ro")
    assert calls[1].endswith("?mode=ro&immutable=1")


def test_all_dashboard_routes_and_assets_require_login(gateway) -> None:
    client, _, _, _, _ = gateway

    expected = {
        "/": "/login?next=/",
        "/api/v1/summary": "/login?next=/api/v1/summary",
        "/static/app.css": "/login?next=/static/app.css",
    }
    for path, location in expected.items():
        response = client.get(path, follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"] == location
        assert response.headers["cache-control"] == "no-store"


def test_login_page_has_generic_copy_csrf_and_security_headers(gateway) -> None:
    client, _, _, _, _ = gateway

    response = client.get("/login")

    assert response.status_code == 200
    assert "請使用此服務的管理員帳號" in response.text
    assert "Podcast" not in response.text
    assert "allenfuhome" not in response.text.lower()
    assert 'name="csrf_token"' in response.text
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert response.headers["strict-transport-security"] == "max-age=31536000"
    assert response.headers["cross-origin-opener-policy"] == "same-origin"
    assert response.headers["cross-origin-resource-policy"] == "same-origin"
    assert response.headers["x-robots-tag"] == "noindex, nofollow, noarchive"


def test_factory_creates_private_session_secret(gateway) -> None:
    _, _, _, settings, _ = gateway

    assert stat.S_IMODE(settings.secret_path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(settings.secret_path.stat().st_mode) == 0o600
    assert len(settings.secret_path.read_text(encoding="utf-8").strip()) >= 32


def test_factory_rejects_insecure_existing_session_secret(tmp_path) -> None:
    database_path = tmp_path / "accounts.sqlite3"
    create_account_database(database_path)
    settings = gateway_settings(tmp_path, database_path)
    settings.secret_path.parent.mkdir(mode=0o700)
    settings.secret_path.write_text("x" * 64, encoding="utf-8")
    settings.secret_path.chmod(0o644)

    with pytest.raises(PrivateFileError):
        auth_gateway.create_app(settings)


def test_forwarded_http_is_redirected_to_canonical_https(gateway) -> None:
    client, _, _, _, _ = gateway

    response = client.get(
        "/login?next=/api/v1/sites",
        headers={"x-forwarded-proto": "http"},
        follow_redirects=False,
    )

    assert response.status_code == 308
    assert response.headers["location"] == (
        "https://sites.example.com/login?next=/api/v1/sites"
    )
    assert response.headers["strict-transport-security"] == "max-age=31536000"


def test_login_rejects_missing_csrf(gateway) -> None:
    client, _, _, _, _ = gateway

    response = client.post(
        "/login",
        data={"username": "operator", "password": TEST_PASSWORD},
    )

    assert response.status_code == 400


def test_valid_argon2_login_sets_private_cookie(gateway) -> None:
    client, _, _, _, _ = gateway

    response = log_in(client)

    assert response.status_code == 303
    assert response.headers["location"] == "/"
    cookie = response.headers["set-cookie"].lower()
    assert "sites_hub_session=" in cookie
    assert "httponly" in cookie
    assert "secure" in cookie
    assert "samesite=lax" in cookie
    assert "max-age=86400" in cookie


def test_logout_clears_session(gateway) -> None:
    client, _, _, _, _ = gateway
    assert log_in(client).status_code == 303

    logout = client.get("/logout", follow_redirects=False)
    after = client.get("/", follow_redirects=False)

    assert logout.status_code == 303
    assert logout.headers["location"] == "/login"
    assert after.status_code == 303
    assert after.headers["location"] == "/login?next=/"


def test_session_version_change_invalidates_existing_session(gateway) -> None:
    client, database_path, _, _, runtime = gateway
    assert log_in(client).status_code == 303
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "UPDATE admin_account SET session_version = session_version + 1"
        )
    runtime.accounts.reset_memory_cache()

    response = client.get("/", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login?next=/"


@pytest.mark.parametrize(
    ("candidate", "expected"),
    [
        ("/sites/stock-dashboard?refresh=off", "/sites/stock-dashboard?refresh=off"),
        ("https://evil.example", "/"),
        ("//evil.example", "/"),
        (r"/\evil.example", "/"),
        (None, "/"),
    ],
)
def test_safe_next_accepts_only_local_paths(candidate, expected) -> None:
    assert auth_gateway.safe_next(candidate) == expected


def test_protected_account_cache_survives_database_outage(gateway) -> None:
    _, _, tmp_path, settings, runtime = gateway
    expected = runtime.accounts.get()
    assert expected is not None
    assert settings.cache_path.exists()
    assert stat.S_IMODE(settings.cache_path.stat().st_mode) == 0o600

    runtime.accounts.settings = replace(
        settings,
        database_path=tmp_path / "missing.sqlite3",
    )
    runtime.accounts.reset_memory_cache()

    assert runtime.accounts.get() == expected


def test_insecure_cache_fails_closed_during_database_outage(tmp_path) -> None:
    settings = gateway_settings(tmp_path, tmp_path / "missing.sqlite3")
    application = auth_gateway.create_app(settings)
    outside = tmp_path / "outside-cache.json"
    outside.write_text("{}", encoding="utf-8")
    outside.chmod(0o600)
    settings.cache_path.symlink_to(outside)

    with TestClient(application, base_url="https://sites.test") as client:
        token = csrf(client)
        response = client.post(
            "/login",
            data={
                "csrf_token": token,
                "username": "operator",
                "password": TEST_PASSWORD,
            },
        )

    assert response.status_code == 503


def test_health_checks_account_and_origin(gateway) -> None:
    client, _, _, _, _ = gateway
    client.app.state.client.get = AsyncMock(
        return_value=httpx.Response(200, json={"status": "ok"})
    )

    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["strict-transport-security"] == "max-age=31536000"


def test_client_key_trusts_valid_cloudflare_ip_only_from_loopback() -> None:
    trusted = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/login",
            "headers": [(b"cf-connecting-ip", b"203.0.113.20")],
            "client": ("127.0.0.1", 12345),
            "server": ("127.0.0.1", 9621),
            "scheme": "http",
        }
    )
    spoofed = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/login",
            "headers": [(b"cf-connecting-ip", b"203.0.113.21")],
            "client": ("198.51.100.9", 12345),
            "server": ("127.0.0.1", 9621),
            "scheme": "http",
        }
    )
    invalid = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/login",
            "headers": [(b"cf-connecting-ip", b"not-an-ip")],
            "client": ("127.0.0.1", 12345),
            "server": ("127.0.0.1", 9621),
            "scheme": "http",
        }
    )

    assert auth_gateway.client_key(trusted) == "203.0.113.20"
    assert auth_gateway.client_key(spoofed) == "198.51.100.9"
    assert auth_gateway.client_key(invalid) == "127.0.0.1"


def test_failure_cache_is_bounded(monkeypatch) -> None:
    monkeypatch.setattr(auth_gateway, "MAX_FAILURE_KEYS", 3)
    failures: dict[str, deque[float]] = {}

    for index in range(5):
        auth_gateway.record_failure(failures, f"198.51.100.{index + 1}")

    assert len(failures) == 3


def test_proxy_drops_client_forwarding_headers_and_uses_fixed_host(gateway) -> None:
    client, _, _, _, _ = gateway
    assert log_in(client).status_code == 303
    client.app.state.client.request = AsyncMock(
        return_value=httpx.Response(200, text="ok")
    )

    response = client.get(
        "/api/v1/summary",
        headers={
            "host": "attacker.example",
            "x-forwarded-for": "203.0.113.10",
            "x-real-ip": "203.0.113.11",
            "cf-connecting-ip": "203.0.113.12",
        },
    )

    assert response.status_code == 200
    forwarded = client.app.state.client.request.await_args.kwargs["headers"]
    assert forwarded["host"] == "sites.example.com"
    assert forwarded["x-forwarded-proto"] == "https"
    assert "x-forwarded-for" not in forwarded
    assert "x-real-ip" not in forwarded
    assert "cf-connecting-ip" not in forwarded


def test_gateway_does_not_proxy_mutating_methods(gateway) -> None:
    client, _, _, _, _ = gateway

    assert client.post("/api/v1/sites").status_code == 405
    assert client.put("/api/v1/sites").status_code == 405
    assert client.delete("/api/v1/sites").status_code == 405
