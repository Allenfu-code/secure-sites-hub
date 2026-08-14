from pathlib import Path

import pytest
from pydantic import ValidationError

from app.models import Registry
from app.registry import RegistryStore

ROOT = Path(__file__).resolve().parents[1]


def _site(site_id: str = "example") -> dict:
    return {
        "id": site_id,
        "name": "Example",
        "category": "public",
        "lifecycle": "production",
        "visibility": "public",
        "urls": [{"url": "https://example.com"}],
    }


def test_example_registry_is_valid_and_synthetic() -> None:
    path = ROOT / "sites.example.yaml"
    registry = RegistryStore(path).load(force=True)

    assert registry.version == 1
    assert [site.id for site in registry.sites] == [
        "example-storefront",
        "example-api",
        "example-archive",
    ]
    assert registry.sites[0].urls[0].url == "https://example.com"
    assert all(
        url.url == "https://example.com" for site in registry.sites for url in site.urls
    )

    registry_text = path.read_text(encoding="utf-8").lower()
    assert "allenfu" not in registry_text
    assert "/home/" not in registry_text
    assert "/mnt/" not in registry_text
    assert "token" not in registry_text
    assert "secret" not in registry_text


def test_registry_rejects_duplicate_site_ids() -> None:
    payload = {"version": 1, "sites": [_site("duplicate"), _site("duplicate")]}

    with pytest.raises(ValidationError, match="site ids must be unique"):
        Registry.model_validate(payload)


def test_registry_rejects_an_invalid_url() -> None:
    payload = {"version": 1, "sites": [_site()]}
    payload["sites"][0]["urls"][0]["url"] = "example.com"

    with pytest.raises(
        ValidationError, match="URL must start with http:// or https://"
    ):
        Registry.model_validate(payload)
