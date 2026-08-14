import socket

import pytest

from app import probes
from app.models import ComponentSpec, UrlSpec


def _answer(address: str):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    return (family, socket.SOCK_STREAM, 6, "", (address, 443))


@pytest.mark.parametrize(
    "url",
    [
        "https://user@example.com/",
        "https://user:password@example.com/",
        "http://localhost/",
        "http://service.localhost/",
        "http://127.0.0.1/",
        "http://10.0.0.1/",
        "http://169.254.20.10/",
        "http://[::1]/",
        "http://[fe80::1]/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::ffff:169.254.169.254]/latest/meta-data/",
    ],
)
def test_probe_destination_blocks_unsafe_urls(url: str) -> None:
    with pytest.raises(probes.UnsafeProbeTarget):
        probes.validate_probe_destination(url, allow_private=False)


def test_probe_destination_blocks_any_non_global_dns_answer() -> None:
    def resolver(*args, **kwargs):
        return [_answer("93.184.216.34"), _answer("192.168.1.10")]

    with pytest.raises(probes.UnsafeProbeTarget, match="non-public"):
        probes.validate_probe_destination(
            "https://example.com",
            allow_private=False,
            resolver=resolver,
        )


def test_probe_destination_accepts_only_global_dns_answers() -> None:
    def resolver(*args, **kwargs):
        return [_answer("93.184.216.34"), _answer("2606:2800:220:1::1")]

    addresses = probes.validate_probe_destination(
        "https://example.com",
        allow_private=False,
        resolver=resolver,
    )

    assert {str(address) for address in addresses} == {
        "93.184.216.34",
        "2606:2800:220:1::1",
    }


def test_private_probe_requires_explicit_environment_opt_in(monkeypatch) -> None:
    monkeypatch.delenv("SITES_HUB_ALLOW_PRIVATE_HTTP", raising=False)
    with pytest.raises(probes.UnsafeProbeTarget):
        probes.validate_probe_destination("http://127.0.0.1:8080")

    monkeypatch.setenv("SITES_HUB_ALLOW_PRIVATE_HTTP", "true")
    assert probes.validate_probe_destination("http://127.0.0.1:8080")


def test_private_opt_in_still_blocks_metadata_and_userinfo(monkeypatch) -> None:
    monkeypatch.setenv("SITES_HUB_ALLOW_PRIVATE_HTTP", "true")

    with pytest.raises(probes.UnsafeProbeTarget, match="metadata"):
        probes.validate_probe_destination("http://169.254.169.254/")
    with pytest.raises(probes.UnsafeProbeTarget, match="metadata"):
        probes.validate_probe_destination("http://[::ffff:169.254.169.254]/")
    with pytest.raises(probes.UnsafeProbeTarget, match="credentials"):
        probes.validate_probe_destination("http://user@127.0.0.1/")


async def test_probe_http_does_not_open_client_for_blocked_target(
    monkeypatch,
) -> None:
    class UnexpectedClient:
        def __init__(self, *args, **kwargs):
            raise AssertionError("HTTP client must not be opened")

    monkeypatch.setattr(probes.httpx, "AsyncClient", UnexpectedClient)

    result = await probes.probe_http(UrlSpec(url="http://127.0.0.1/"))

    assert result.status == "down"
    assert result.detail == "已阻擋不安全的探測目標"


async def test_windows_probe_requires_explicit_powershell_path(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.delenv("SITES_HUB_POWERSHELL_PATH", raising=False)

    async def unexpected(*args, **kwargs):
        raise AssertionError("no subprocess should run without an opt-in path")

    monkeypatch.setattr(probes, "run_readonly", unexpected)

    assert (
        await probes.collect_windows_listeners(
            [8080],
            tmp_path / "probe.ps1",
        )
        == {}
    )


def test_probe_request_is_pinned_without_losing_host_or_sni() -> None:
    url, headers, extensions = probes.pinned_probe_request(
        "https://example.com:8443/health?full=false",
        probes.ipaddress.ip_address("93.184.216.34"),
    )

    assert url == "https://93.184.216.34:8443/health?full=false"
    assert headers == {"Host": "example.com:8443"}
    assert extensions == {"sni_hostname": "example.com"}


async def test_probe_component_accepts_active_systemd_timer(monkeypatch) -> None:
    commands: list[list[str]] = []

    async def fake_run_readonly(command: list[str], timeout: float = 6.0):
        commands.append(command)
        return 0, "active", ""

    monkeypatch.setattr(probes, "run_readonly", fake_run_readonly)
    spec = ComponentSpec(
        id="scheduled-job",
        name="Scheduled job",
        platform="wsl",
        kind="systemd_user",
        target="scheduled-job.timer",
    )

    result = await probes.probe_component(spec, {})

    assert result.status == "healthy"
    assert commands == [["systemctl", "--user", "is-active", "scheduled-job.timer"]]


async def test_probe_component_rejects_unsafe_systemd_timer(monkeypatch) -> None:
    async def unexpected_run_readonly(command: list[str], timeout: float = 6.0):
        raise AssertionError(f"unexpected command: {command}")

    monkeypatch.setattr(probes, "run_readonly", unexpected_run_readonly)
    spec = ComponentSpec(
        id="scheduled-job",
        name="Scheduled job",
        platform="wsl",
        kind="systemd_user",
        target="../scheduled-job.timer",
    )

    result = await probes.probe_component(spec, {})

    assert result.status == "unknown"
    assert result.detail == "不安全的 systemd 單元名稱"
