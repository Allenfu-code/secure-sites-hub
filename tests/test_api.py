import importlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock

import fastapi.staticfiles
import pytest
from fastapi import HTTPException
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from app.models import CheckResult, ComponentSpec, SiteSpec

ROOT = Path(__file__).resolve().parents[1]


class _EmptyStaticFiles:
    """Fallback ASGI app so API tests can report backend failures independently."""

    def __init__(self, *args, **kwargs) -> None:
        pass

    async def __call__(self, scope, receive, send) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 404,
                "headers": [(b"content-type", b"text/plain")],
            }
        )
        await send({"type": "http.response.body", "body": b"Not Found"})


@pytest.fixture()
def api_client(monkeypatch, tmp_path):
    monkeypatch.setenv("SITES_HUB_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SITES_HUB_REGISTRY", str(ROOT / "sites.example.yaml"))
    monkeypatch.setenv("CLOUDFLARE_ACCESS_REQUIRED", "false")
    if not (ROOT / "static").is_dir():
        monkeypatch.setattr(
            fastapi.staticfiles,
            "StaticFiles",
            _EmptyStaticFiles,
        )
    sys.modules.pop("app.main", None)
    main = importlib.import_module("app.main")
    monkeypatch.setattr(main.service, "start", AsyncMock())
    monkeypatch.setattr(main.service, "stop", AsyncMock())
    monkeypatch.setattr(main.access_verifier, "verify", AsyncMock())

    with TestClient(main.app) as client:
        yield client, main

    sys.modules.pop("app.main", None)


def test_healthz_is_available_without_background_probes(api_client) -> None:
    client, _ = api_client

    response = client.get("/healthz")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["sites"] == 0
    assert payload["generated_at"]
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"


def test_read_only_api_get_routes_respond(api_client) -> None:
    client, _ = api_client

    assert client.get("/api/v1/summary").status_code == 200
    assert client.get("/api/v1/sites").json()["items"] == []
    assert client.get("/api/v1/candidates").status_code == 404
    assert client.get("/api/v1/sites/missing").status_code == 404


def _seed_sensitive_site(main) -> tuple[str, ...]:
    secrets = (
        "/private/source/DO-NOT-EXPOSE",
        "private-daemon.service",
        "INTERNAL-CHECK-DETAIL",
        "INTERNAL-NOTE",
        "INTERNAL-DEPENDENCY",
    )
    site = SiteSpec(
        id="public-example",
        name="Public Example",
        description="Safe public description",
        category="public",
        lifecycle="production",
        visibility="public",
        urls=[{"url": "https://example.com", "label": "Public URL"}],
        source_paths=[secrets[0]],
        dependencies=[secrets[4]],
        components=[
            ComponentSpec(
                id="origin",
                name="Origin",
                platform="wsl",
                kind="systemd_user",
                target=secrets[1],
            )
        ],
        notes=secrets[3],
    )
    checks = [
        CheckResult(
            name="Public URL",
            target="https://example.com",
            status="healthy",
            status_label="正常",
            detail="HTTP 200",
            check_type="public_http",
        ),
        CheckResult(
            name="Origin",
            target=secrets[1],
            status="healthy",
            status_label="正常",
            detail=secrets[2],
            check_type="systemd_user",
        ),
    ]
    main.service.current[site.id] = main.service._make_site_view(
        site,
        checks,
        datetime.now(UTC).isoformat(),
    )
    return secrets


def _all_keys(value):
    if isinstance(value, dict):
        yield from value.keys()
        for nested in value.values():
            yield from _all_keys(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _all_keys(nested)


def test_public_api_uses_allowlisted_dtos_without_internals(api_client) -> None:
    client, main = api_client
    secrets = _seed_sensitive_site(main)

    list_payload = client.get("/api/v1/sites").json()
    detail_payload = client.get("/api/v1/sites/public-example").json()

    forbidden_keys = {
        "source_paths",
        "target",
        "detail",
        "notes",
        "dependencies",
        "candidates",
    }
    assert forbidden_keys.isdisjoint(set(_all_keys(list_payload)))
    assert forbidden_keys.isdisjoint(set(_all_keys(detail_payload)))
    serialized = json.dumps(
        {"list": list_payload, "detail": detail_payload},
        ensure_ascii=False,
    )
    assert all(secret not in serialized for secret in secrets)
    assert detail_payload["item"]["urls"] == [
        {"url": "https://example.com", "label": "Public URL"}
    ]


def test_public_html_does_not_render_internal_values(api_client) -> None:
    client, main = api_client
    secrets = _seed_sensitive_site(main)

    dashboard = client.get("/")
    detail = client.get("/sites/public-example")

    assert dashboard.status_code == 200
    assert detail.status_code == 200
    combined = f"{dashboard.text}\n{detail.text}"
    assert all(secret not in combined for secret in secrets)


def test_candidates_require_discovery_and_internal_exposure(api_client) -> None:
    client, main = api_client
    main.service.history.upsert_candidates(
        [
            {
                "fingerprint": "project:test",
                "kind": "project",
                "name": "Private candidate",
                "target": "/private/candidate",
                "detail": {"source": "/private/source"},
            }
        ],
        datetime.now(UTC).isoformat(),
    )

    main.service.discovery_enabled = True
    main.service.expose_internals = False
    assert client.get("/api/v1/candidates").status_code == 404

    main.service.expose_internals = True
    response = client.get("/api/v1/candidates")
    assert response.status_code == 200
    assert response.json()["items"][0]["fingerprint"] == "project:test"


def test_application_exposes_no_mutating_api_methods(api_client) -> None:
    client, main = api_client
    api_routes = [
        route
        for route in main.app.routes
        if isinstance(route, APIRoute)
        and (
            route.path.startswith("/api/")
            or route.path in {"/", "/healthz"}
            or route.path.startswith("/sites/")
        )
    ]

    assert api_routes
    assert {method for route in api_routes for method in route.methods} == {"GET"}

    for method in ("post", "put", "delete"):
        response = getattr(client, method)("/api/v1/sites")
        assert response.status_code == 405


def test_access_rejection_is_fail_closed_without_server_error(api_client) -> None:
    client, main = api_client
    main.access_verifier.verify.side_effect = HTTPException(
        status_code=403,
        detail="Cloudflare Access required",
    )

    response = client.get("/")

    assert response.status_code == 403
    assert response.json() == {"detail": "Cloudflare Access required"}
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["cache-control"] == "no-store"
