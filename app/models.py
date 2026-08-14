from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

Status = Literal["healthy", "degraded", "down", "unknown"]


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


class UrlSpec(BaseModel):
    url: str
    label: str = "開啟網站"
    required: bool = True
    expected_status: list[int] = Field(default_factory=lambda: list(range(200, 400)))

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        if not value.startswith(("https://", "http://")):
            raise ValueError("URL must start with http:// or https://")
        return value


class ComponentSpec(BaseModel):
    id: str
    name: str
    platform: Literal["windows", "wsl", "docker", "cloudflare", "filesystem"]
    kind: Literal[
        "windows_port",
        "wsl_port",
        "systemd_user",
        "systemd_system",
        "docker",
        "path",
    ]
    target: str
    required: bool = True
    description: str = ""

    @field_validator("id", "target")
    @classmethod
    def reject_control_characters(cls, value: str) -> str:
        if any(char in value for char in ("\x00", "\n", "\r")):
            raise ValueError("control characters are not allowed")
        return value


class SiteSpec(BaseModel):
    id: str
    name: str
    description: str = ""
    category: Literal[
        "public",
        "protected",
        "internal",
        "api",
        "infrastructure",
        "archived",
    ]
    lifecycle: Literal[
        "production",
        "internal",
        "development",
        "maintenance",
        "archived",
    ]
    visibility: Literal["public", "protected", "private", "local"]
    urls: list[UrlSpec] = Field(default_factory=list)
    source_paths: list[str] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)
    components: list[ComponentSpec] = Field(default_factory=list)
    notes: str = ""


class Registry(BaseModel):
    version: int = 1
    sites: list[SiteSpec]

    @field_validator("sites")
    @classmethod
    def unique_site_ids(cls, sites: list[SiteSpec]) -> list[SiteSpec]:
        ids = [site.id for site in sites]
        if len(ids) != len(set(ids)):
            raise ValueError("site ids must be unique")
        return sites


class CheckResult(BaseModel):
    name: str
    target: str
    status: Status
    status_label: str
    checked_at: str = Field(default_factory=utc_now_iso)
    latency_ms: int | None = None
    detail: str = ""
    required: bool = True
    check_type: str = ""


class ComponentView(BaseModel):
    id: str
    name: str
    platform: str
    kind: str
    target: str
    status: Status
    status_label: str
    detail: str = ""
    required: bool = True


class SiteView(BaseModel):
    id: str
    name: str
    description: str
    category: str
    category_label: str
    lifecycle: str
    status: Status
    status_label: str
    visibility: str
    urls: list[dict]
    source_paths: list[str]
    dependencies: list[str]
    components: list[ComponentView]
    checks: list[CheckResult]
    last_checked_at: str
    uptime_24h: float | None = None
    uptime_90d: float | None = None
    is_candidate: bool = False
    notes: str = ""
