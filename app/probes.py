from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import socket
import time
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import httpx

from .models import CheckResult, ComponentSpec, UrlSpec, utc_now_iso
from .settings import env_enabled

STATUS_LABELS = {
    "healthy": "正常",
    "degraded": "部分異常",
    "down": "離線",
    "unknown": "未知",
}

SAFE_UNIT_RE = re.compile(r"^[A-Za-z0-9_.@:-]+\.(?:service|timer)$")
SAFE_CONTAINER_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
METADATA_HOSTNAMES = frozenset(
    {
        "metadata",
        "metadata.google.internal",
        "metadata.goog",
        "instance-data",
        "instance-data.ec2.internal",
        "metadata.azure.internal",
    }
)
METADATA_ADDRESSES = frozenset(
    {
        ipaddress.ip_address("169.254.169.254"),
        ipaddress.ip_address("169.254.170.2"),
        ipaddress.ip_address("100.100.100.200"),
    }
)


class UnsafeProbeTarget(ValueError):
    """Raised when a URL could reach a non-public network destination."""


def validate_probe_destination(
    url: str,
    *,
    allow_private: bool | None = None,
    resolver=None,
) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
    """Resolve and validate a probe URL before making a network request.

    Private probing is disabled by default. Metadata endpoints and URL
    credentials remain blocked even when private probes are explicitly enabled.
    """

    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise UnsafeProbeTarget("invalid URL") from exc
    if parsed.scheme not in {"http", "https"} or not host:
        raise UnsafeProbeTarget("only HTTP(S) URLs with a host are allowed")
    if parsed.username is not None or parsed.password is not None:
        raise UnsafeProbeTarget("URL credentials are not allowed")

    normalized_host = host.rstrip(".").lower()
    if normalized_host in METADATA_HOSTNAMES or normalized_host.endswith(
        ".metadata.google.internal"
    ):
        raise UnsafeProbeTarget("metadata endpoints are not allowed")

    allow_private = (
        env_enabled("SITES_HUB_ALLOW_PRIVATE_HTTP")
        if allow_private is None
        else allow_private
    )
    is_local_name = normalized_host == "localhost" or normalized_host.endswith(
        ".localhost"
    )
    if is_local_name and not allow_private:
        raise UnsafeProbeTarget("local destinations are not allowed")

    try:
        addresses = (ipaddress.ip_address(normalized_host),)
    except ValueError:
        resolve = resolver or socket.getaddrinfo
        service_port = port or (443 if parsed.scheme == "https" else 80)
        try:
            answers = resolve(
                normalized_host,
                service_port,
                type=socket.SOCK_STREAM,
            )
        except (OSError, UnicodeError) as exc:
            raise UnsafeProbeTarget("destination could not be resolved") from exc
        resolved: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
        for answer in answers:
            try:
                value = str(answer[4][0]).split("%", 1)[0]
                resolved.add(ipaddress.ip_address(value))
            except (IndexError, TypeError, ValueError):
                raise UnsafeProbeTarget("resolver returned an invalid address")
        if not resolved:
            raise UnsafeProbeTarget("destination did not resolve")
        addresses = tuple(sorted(resolved, key=lambda item: (item.version, int(item))))

    effective_addresses = tuple(
        address.ipv4_mapped
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped
        else address
        for address in addresses
    )
    if any(address in METADATA_ADDRESSES for address in effective_addresses):
        raise UnsafeProbeTarget("metadata endpoints are not allowed")
    if not allow_private and any(
        not address.is_global for address in effective_addresses
    ):
        raise UnsafeProbeTarget("non-public destinations are not allowed")
    return addresses


def pinned_probe_request(
    url: str,
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> tuple[str, dict[str, str], dict[str, str]]:
    """Build a request pinned to an already validated IP address.

    Keeping the original Host and SNI values preserves virtual hosting and TLS
    verification while avoiding a second, potentially rebound DNS lookup.
    """

    parsed = urlsplit(url)
    original_host = (parsed.hostname or "").rstrip(".").encode("idna").decode()
    default_port = 443 if parsed.scheme == "https" else 80
    port = parsed.port or default_port
    host_header = f"[{original_host}]" if ":" in original_host else original_host
    if port != default_port:
        host_header = f"{host_header}:{port}"
    address_host = f"[{address}]" if address.version == 6 else str(address)
    netloc = address_host if port == default_port else f"{address_host}:{port}"
    pinned_url = urlunsplit(
        (parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment)
    )
    return (
        pinned_url,
        {"Host": host_header},
        {"sni_hostname": original_host},
    )


async def run_readonly(
    command: list[str], timeout: float = 6.0
) -> tuple[int, str, str]:
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        return (
            process.returncode or 0,
            stdout.decode("utf-8", errors="replace").strip(),
            stderr.decode("utf-8", errors="replace").strip(),
        )
    except (TimeoutError, FileNotFoundError, PermissionError) as exc:
        return 124, "", type(exc).__name__


async def probe_http(url_spec: UrlSpec) -> CheckResult:
    started = time.perf_counter()
    status = "down"
    detail = "尚未檢查"
    try:
        addresses = await asyncio.to_thread(
            validate_probe_destination,
            url_spec.url,
        )
    except UnsafeProbeTarget:
        latency = round((time.perf_counter() - started) * 1000)
        return CheckResult(
            name=url_spec.label,
            target=url_spec.url,
            status="down",
            status_label=STATUS_LABELS["down"],
            latency_ms=latency,
            detail="已阻擋不安全的探測目標",
            required=url_spec.required,
            check_type="public_http",
        )
    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=httpx.Timeout(8.0),
        headers={"User-Agent": "AllenFu-Sites-Hub/1.0"},
        trust_env=False,
    ) as client:
        for attempt in range(2):
            try:
                pinned_url, headers, extensions = pinned_probe_request(
                    url_spec.url,
                    addresses[attempt % len(addresses)],
                )
                response = await client.get(
                    pinned_url,
                    headers=headers,
                    extensions=extensions,
                )
                ok = response.status_code in set(url_spec.expected_status)
                status = "healthy" if ok else "down"
                detail = f"HTTP {response.status_code}"
                if ok or response.status_code < 500:
                    break
            except (httpx.HTTPError, OSError) as exc:
                detail = type(exc).__name__
            if attempt == 0:
                await asyncio.sleep(0.35)
    latency = round((time.perf_counter() - started) * 1000)
    return CheckResult(
        name=url_spec.label,
        target=url_spec.url,
        status=status,
        status_label=STATUS_LABELS[status],
        latency_ms=latency,
        detail=detail,
        required=url_spec.required,
        check_type="public_http",
    )


async def probe_tcp(host: str, port: int, name: str, required: bool) -> CheckResult:
    started = time.perf_counter()

    def connect() -> None:
        with socket.create_connection((host, port), timeout=3.0):
            return None

    try:
        await asyncio.to_thread(connect)
        latency = round((time.perf_counter() - started) * 1000)
        status = "healthy"
        detail = f"{host}:{port} 正在監聽"
    except OSError as exc:
        latency = round((time.perf_counter() - started) * 1000)
        status = "down"
        detail = type(exc).__name__
    return CheckResult(
        name=name,
        target=f"{host}:{port}",
        status=status,
        status_label=STATUS_LABELS[status],
        latency_ms=latency,
        detail=detail,
        required=required,
        check_type="tcp",
    )


async def collect_windows_listeners(
    ports: Iterable[int], script_path: Path
) -> dict[int, list[dict]]:
    clean_ports = sorted({int(port) for port in ports if 1 <= int(port) <= 65535})
    if not clean_ports:
        return {}
    powershell = os.getenv("SITES_HUB_POWERSHELL_PATH", "").strip()
    if not powershell:
        return {}
    code, windows_path, _ = await run_readonly(
        ["wslpath", "-w", str(script_path)], timeout=3
    )
    if code != 0 or not windows_path:
        return {}
    code, output, _ = await run_readonly(
        [
            powershell,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            windows_path,
            "-Ports",
            ",".join(str(port) for port in clean_ports),
        ],
        timeout=10,
    )
    if code != 0 or not output:
        return {}
    try:
        payload = json.loads(output)
    except json.JSONDecodeError:
        return {}
    rows = payload if isinstance(payload, list) else [payload]
    result: dict[int, list[dict]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        try:
            port = int(row.get("port"))
        except (TypeError, ValueError):
            continue
        result.setdefault(port, []).append(
            {
                "address": str(row.get("address", "")),
                "pid": int(row.get("pid") or 0),
                "process": str(row.get("process", ""))[:80],
            }
        )
    return result


async def probe_component(
    spec: ComponentSpec,
    windows_listeners: dict[int, list[dict]],
) -> CheckResult:
    checked_at = utc_now_iso()
    if spec.kind == "windows_port":
        try:
            port = int(spec.target)
        except ValueError:
            port = -1
        rows = windows_listeners.get(port, [])
        if rows:
            names = sorted({row["process"] for row in rows if row["process"]})
            detail = f"Windows :{port} · {', '.join(names) or 'process'}"
            status = "healthy"
        else:
            detail = f"Windows :{port} 未監聽"
            status = "down"
        return CheckResult(
            name=spec.name,
            target=f"Windows :{port}",
            status=status,
            status_label=STATUS_LABELS[status],
            checked_at=checked_at,
            detail=detail,
            required=spec.required,
            check_type=spec.kind,
        )

    if spec.kind == "wsl_port":
        try:
            port = int(spec.target)
        except ValueError:
            port = -1
        return await probe_tcp("127.0.0.1", port, spec.name, spec.required)

    if spec.kind in {"systemd_user", "systemd_system"}:
        if not SAFE_UNIT_RE.fullmatch(spec.target):
            status = "unknown"
            detail = "不安全的 systemd 單元名稱"
        else:
            command = ["systemctl"]
            if spec.kind == "systemd_user":
                command.append("--user")
            command.extend(["is-active", spec.target])
            code, output, _ = await run_readonly(command, timeout=5)
            status = "healthy" if code == 0 and output == "active" else "down"
            detail = output or "inactive"
        return CheckResult(
            name=spec.name,
            target=spec.target,
            status=status,
            status_label=STATUS_LABELS[status],
            checked_at=checked_at,
            detail=detail,
            required=spec.required,
            check_type=spec.kind,
        )

    if spec.kind == "docker":
        if not SAFE_CONTAINER_RE.fullmatch(spec.target):
            status = "unknown"
            detail = "不安全的容器名稱"
        else:
            code, output, _ = await run_readonly(
                [
                    "docker",
                    "inspect",
                    "--format",
                    "{{.State.Status}}",
                    spec.target,
                ],
                timeout=5,
            )
            status = "healthy" if code == 0 and output == "running" else "down"
            detail = output or "not found"
        return CheckResult(
            name=spec.name,
            target=spec.target,
            status=status,
            status_label=STATUS_LABELS[status],
            checked_at=checked_at,
            detail=detail,
            required=spec.required,
            check_type=spec.kind,
        )

    if spec.kind == "path":
        exists = await asyncio.to_thread(Path(spec.target).exists)
        status = "healthy" if exists else "down"
        return CheckResult(
            name=spec.name,
            target=spec.target,
            status=status,
            status_label=STATUS_LABELS[status],
            checked_at=checked_at,
            detail="路徑存在" if exists else "路徑不存在",
            required=spec.required,
            check_type=spec.kind,
        )

    return CheckResult(
        name=spec.name,
        target=spec.target,
        status="unknown",
        status_label=STATUS_LABELS["unknown"],
        checked_at=checked_at,
        detail="未支援的檢查類型",
        required=spec.required,
        check_type=spec.kind,
    )
