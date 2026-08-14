from __future__ import annotations

import hmac
import html
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import time
from collections import deque
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote, urlsplit

import httpx
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.middleware.sessions import SessionMiddleware

from .private_files import (
    PrivateFileError,
    atomic_write_private_text,
    read_private_text,
)

APP_ROOT = Path(__file__).resolve().parent.parent
COOKIE_NAME = "sites_hub_session"
SESSION_SECONDS = 24 * 60 * 60
MAX_FAILURES = 5
FAILURE_WINDOW_SECONDS = 15 * 60
MAX_FAILURE_KEYS = 2048
ACCOUNT_CACHE_SECONDS = 30
PASSWORD_HASHER = PasswordHasher()

HOP_BY_HOP_HEADERS = {
    "connection",
    "content-encoding",
    "content-length",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}
UNTRUSTED_PROXY_HEADERS = {
    "cf-connecting-ip",
    "cf-ipcountry",
    "cf-ray",
    "cf-visitor",
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-port",
    "x-forwarded-proto",
    "x-real-ip",
}
SECURITY_HEADERS = {
    "content-security-policy": (
        "default-src 'self'; script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "connect-src 'self'; object-src 'none'; base-uri 'self'; "
        "frame-ancestors 'none'; form-action 'self'"
    ),
    "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "referrer-policy": "no-referrer",
    "strict-transport-security": "max-age=31536000",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "x-robots-tag": "noindex, nofollow, noarchive",
    "x-permitted-cross-domain-policies": "none",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
}


def _environment_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise RuntimeError(f"{name} must be a boolean value.")


@dataclass(frozen=True)
class GatewaySettings:
    database_path: Path = APP_ROOT / "runtime" / "accounts.sqlite3"
    secret_path: Path = APP_ROOT / "runtime" / ".session-secret"
    cache_path: Path = APP_ROOT / "runtime" / ".auth-cache.json"
    upstream: str = "http://127.0.0.1:9620"
    public_host: str = "sites.example.com"
    database_immutable: bool = False

    def __post_init__(self) -> None:
        host = self.public_host.strip().lower()
        if not re.fullmatch(
            r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?",
            host,
        ):
            raise ValueError("public_host must be a hostname without a scheme or path.")
        upstream = self.upstream.rstrip("/")
        try:
            parsed_upstream = urlsplit(upstream)
            upstream_host = parsed_upstream.hostname
            upstream_port = parsed_upstream.port
            upstream_address = ipaddress.ip_address(upstream_host or "")
        except ValueError as exc:
            raise ValueError(
                "upstream must be a numeric loopback HTTP(S) origin."
            ) from exc
        if (
            parsed_upstream.scheme not in {"http", "https"}
            or not upstream_address.is_loopback
            or upstream_port is None
            or parsed_upstream.username is not None
            or parsed_upstream.password is not None
            or parsed_upstream.path not in {"", "/"}
            or parsed_upstream.query
            or parsed_upstream.fragment
        ):
            raise ValueError(
                "upstream must be a numeric loopback HTTP(S) origin with a port."
            )
        object.__setattr__(self, "database_path", Path(self.database_path))
        object.__setattr__(self, "secret_path", Path(self.secret_path))
        object.__setattr__(self, "cache_path", Path(self.cache_path))
        object.__setattr__(self, "upstream", upstream)
        object.__setattr__(self, "public_host", host)

    @classmethod
    def from_env(cls) -> GatewaySettings:
        runtime = APP_ROOT / "runtime"
        return cls(
            database_path=Path(
                os.environ.get(
                    "SITES_HUB_AUTH_DB",
                    str(runtime / "accounts.sqlite3"),
                )
            ),
            secret_path=Path(
                os.environ.get(
                    "SITES_HUB_SESSION_SECRET_FILE",
                    str(runtime / ".session-secret"),
                )
            ),
            cache_path=Path(
                os.environ.get(
                    "SITES_HUB_AUTH_CACHE_FILE",
                    str(runtime / ".auth-cache.json"),
                )
            ),
            upstream=os.environ.get(
                "SITES_HUB_UPSTREAM",
                "http://127.0.0.1:9620",
            ),
            public_host=os.environ.get(
                "SITES_HUB_PUBLIC_HOST",
                "sites.example.com",
            ),
            database_immutable=_environment_flag(
                "SITES_HUB_AUTH_DB_IMMUTABLE",
            ),
        )


def load_or_create_secret(path: Path) -> str:
    try:
        secret = read_private_text(path).strip()
    except FileNotFoundError:
        atomic_write_private_text(path, secrets.token_urlsafe(64))
        secret = read_private_text(path).strip()
    if len(secret) < 32:
        raise PrivateFileError("Session secret is invalid.")
    return secret


def database_connection(
    path: Path,
    *,
    immutable: bool = False,
) -> sqlite3.Connection:
    database = quote(Path(path).absolute().as_posix(), safe="/:")
    parameters = "mode=ro"
    if immutable:
        parameters += "&immutable=1"
    return sqlite3.connect(f"file:{database}?{parameters}", uri=True)


def write_account_cache(path: Path, account: tuple[str, str, int]) -> None:
    payload = json.dumps(
        {
            "username": account[0],
            "password_hash": account[1],
            "session_version": account[2],
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    atomic_write_private_text(path, f"{payload}\n")


def read_account_cache(path: Path) -> tuple[str, str, int] | None:
    try:
        cached = json.loads(read_private_text(path))
        return (
            str(cached["username"]),
            str(cached["password_hash"]),
            int(cached["session_version"]),
        )
    except FileNotFoundError:
        return None
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None


class AccountStore:
    def __init__(self, settings: GatewaySettings):
        self.settings = settings
        self._account_cache: tuple[str, str, int] | None = None
        self._account_cache_time = 0.0

    def reset_memory_cache(self) -> None:
        self._account_cache = None
        self._account_cache_time = 0.0

    def get(self) -> tuple[str, str, int] | None:
        now = time.monotonic()
        if (
            self._account_cache is not None
            and now - self._account_cache_time < ACCOUNT_CACHE_SECONDS
        ):
            return self._account_cache

        try:
            with database_connection(
                self.settings.database_path,
                immutable=self.settings.database_immutable,
            ) as connection:
                row = connection.execute(
                    "SELECT username, password_hash, session_version "
                    "FROM admin_account LIMIT 1"
                ).fetchone()
            account = (
                (str(row[0]), str(row[1]), int(row[2])) if row is not None else None
            )
            if account is not None:
                write_account_cache(self.settings.cache_path, account)
                self._account_cache = account
                self._account_cache_time = now
            return account
        except (OSError, sqlite3.Error) as database_error:
            try:
                account = self._account_cache or read_account_cache(
                    self.settings.cache_path
                )
            except OSError:
                raise
            if account is None:
                raise database_error
            self._account_cache = account
            self._account_cache_time = now
            return account


@dataclass
class GatewayRuntime:
    settings: GatewaySettings
    accounts: AccountStore
    failures: dict[str, deque[float]] = field(default_factory=dict)


def authenticated(request: Request) -> bool:
    runtime: GatewayRuntime = request.app.state.gateway
    try:
        account = runtime.accounts.get()
    except (OSError, sqlite3.Error):
        return False
    if account is None:
        return False
    username, _, session_version = account
    return bool(
        request.session.get("username") == username
        and request.session.get("session_version") == session_version
    )


def safe_next(value: str | None) -> str:
    if (
        value
        and value.startswith("/")
        and not value.startswith("//")
        and "\\" not in value
        and "\r" not in value
        and "\n" not in value
    ):
        return value
    return "/"


def client_key(request: Request) -> str:
    direct = request.client.host if request.client else "unknown"
    try:
        direct_ip = ipaddress.ip_address(direct)
    except ValueError:
        return direct
    if not direct_ip.is_loopback:
        return str(direct_ip)
    candidate = request.headers.get("cf-connecting-ip", "").strip()
    try:
        return str(ipaddress.ip_address(candidate)) if candidate else str(direct_ip)
    except ValueError:
        return str(direct_ip)


def original_scheme(request: Request) -> tuple[str, bool]:
    direct = request.client.host if request.client else ""
    try:
        if not ipaddress.ip_address(direct).is_loopback:
            return request.url.scheme.lower(), False
    except ValueError:
        return request.url.scheme.lower(), False
    forwarded = request.headers.get("x-forwarded-proto", "").strip().lower()
    if forwarded in {"http", "https"}:
        return forwarded, True
    visitor = request.headers.get("cf-visitor", "")
    try:
        scheme = str(json.loads(visitor).get("scheme", "")).lower()
    except (AttributeError, json.JSONDecodeError, TypeError):
        scheme = ""
    if scheme in {"http", "https"}:
        return scheme, True
    return request.url.scheme.lower(), False


def prune_failures(failures: dict[str, deque[float]], now: float) -> None:
    stale: list[str] = []
    for key, attempts in failures.items():
        while attempts and attempts[0] < now - FAILURE_WINDOW_SECONDS:
            attempts.popleft()
        if not attempts:
            stale.append(key)
    for key in stale:
        failures.pop(key, None)
    while len(failures) > MAX_FAILURE_KEYS:
        oldest = min(failures, key=lambda key: failures[key][-1])
        failures.pop(oldest, None)


def is_rate_limited(failures: dict[str, deque[float]], key: str) -> bool:
    prune_failures(failures, time.monotonic())
    return len(failures.get(key, ())) >= MAX_FAILURES


def record_failure(failures: dict[str, deque[float]], key: str) -> None:
    now = time.monotonic()
    prune_failures(failures, now)
    if key not in failures and len(failures) >= MAX_FAILURE_KEYS:
        oldest = min(failures, key=lambda item: failures[item][-1])
        failures.pop(oldest, None)
    failures.setdefault(key, deque()).append(now)


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not isinstance(token, str) or len(token) < 32:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token
    return token


def secure(response: Response) -> Response:
    for name, value in SECURITY_HEADERS.items():
        if name not in response.headers:
            response.headers[name] = value
    response.headers["cache-control"] = "no-store"
    response.headers["vary"] = "Cookie"
    return response


def login_page(
    request: Request,
    *,
    error: str = "",
    status_code: int = 200,
) -> HTMLResponse:
    next_path = safe_next(request.query_params.get("next"))
    error_markup = (
        f'<p class="error" role="alert">{html.escape(error)}</p>' if error else ""
    )
    document = f"""<!doctype html>
<html lang="zh-Hant">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>安全登入｜Sites Hub</title>
  <style>
    :root{{--ink:#101d31;--muted:#64748b;--cyan:#59d7e8}}
    *{{box-sizing:border-box}}
    body{{min-height:100vh;margin:0;display:grid;place-items:center;padding:24px;
      color:var(--ink);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",
      "Noto Sans TC",sans-serif;background:
      radial-gradient(circle at 12% 0%,#14345b 0,transparent 36rem),
      radial-gradient(circle at 100% 100%,#164e63 0,transparent 34rem),#08111f}}
    main{{width:min(920px,100%);display:grid;grid-template-columns:1.05fr .95fr;
      overflow:hidden;border:1px solid rgba(255,255,255,.12);border-radius:28px;
      background:#fff;box-shadow:0 32px 90px rgba(0,0,0,.38)}}
    .intro{{min-height:540px;padding:58px;display:flex;flex-direction:column;
      justify-content:space-between;color:#fff;background:
      linear-gradient(145deg,#101d31,#0b3550)}}
    .brand{{margin:0;font-size:15px;font-weight:800;letter-spacing:.11em}}
    .eyebrow{{margin:0 0 14px;color:#8eeaf5;font-size:12px;font-weight:800;
      letter-spacing:.16em;text-transform:uppercase}}
    h1{{margin:0 0 18px;font-size:clamp(36px,5vw,54px);line-height:1.08;
      letter-spacing:-.045em}}
    .intro-copy>p:last-child{{margin:0;color:#cbd9e7;line-height:1.75}}
    .login{{padding:58px;display:flex;flex-direction:column;justify-content:center}}
    h2{{margin:0 0 10px;font-size:28px}}.hint{{margin:0 0 30px;color:var(--muted);
      line-height:1.65}}
    label{{display:block;margin:0 0 8px;font-size:14px;font-weight:750}}
    input{{width:100%;height:50px;margin:0 0 19px;padding:0 15px;border:1px solid
      #d8e0e8;border-radius:12px;background:#fff;color:var(--ink);font:inherit}}
    input:focus{{border-color:#168ca0;outline:3px solid rgba(22,140,160,.16)}}
    button{{width:100%;height:50px;border:0;border-radius:12px;color:#fff;
      background:var(--ink);font:inherit;font-weight:780;cursor:pointer}}
    button:hover{{background:#17385c}}.error{{margin:-5px 0 18px;padding:12px 14px;
      border-radius:10px;color:#9f3027;background:#fff0ee;font-size:14px}}
    .privacy{{margin:22px 0 0;color:#7b899b;font-size:12px;line-height:1.6}}
    @media(max-width:720px){{main{{grid-template-columns:1fr}}.intro{{min-height:245px;
      padding:36px 32px}}.login{{padding:40px 32px}}}}
  </style>
</head>
<body>
  <main>
    <section class="intro">
      <p class="brand">SERVICE OBSERVATORY</p>
      <div class="intro-copy">
        <p class="eyebrow">Private operations dashboard</p>
        <h1>所有網站，<br>一眼掌握。</h1>
        <p>登入後即可查看網站、服務、Tunnel 與基礎元件的唯讀健康狀態。</p>
      </div>
    </section>
    <section class="login">
      <h2>安全登入</h2>
      <p class="hint">請使用此服務的管理員帳號。</p>
      {error_markup}
      <form method="post" action="/login?next={quote(next_path, safe="/")}">
        <input type="hidden" name="csrf_token"
          value="{html.escape(csrf_token(request))}">
        <label for="username">帳號</label>
        <input id="username" name="username" autocomplete="username"
          required autofocus>
        <label for="password">密碼</label>
        <input id="password" name="password" type="password"
          autocomplete="current-password" required>
        <button type="submit">登入網站總控中心</button>
      </form>
      <p class="privacy">登入資料只用於本服務的本機驗證，不會傳送至其他服務。</p>
    </section>
  </main>
</body>
</html>"""
    return secure(HTMLResponse(document, status_code=status_code))


def create_app(settings: GatewaySettings | None = None) -> FastAPI:
    """Build the gateway; importing this module performs no secret-file I/O."""

    configured = settings or GatewaySettings.from_env()
    session_secret = load_or_create_secret(configured.secret_path)
    runtime = GatewayRuntime(configured, AccountStore(configured))

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        application.state.client = httpx.AsyncClient(
            timeout=30.0,
            follow_redirects=False,
        )
        yield
        await application.state.client.aclose()

    application = FastAPI(
        title="Secure Sites Hub authentication gateway",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    application.state.gateway = runtime
    application.add_middleware(
        SessionMiddleware,
        secret_key=session_secret,
        session_cookie=COOKIE_NAME,
        max_age=SESSION_SECONDS,
        same_site="lax",
        https_only=True,
    )

    @application.middleware("http")
    async def enforce_https_and_security(
        request: Request,
        call_next,
    ) -> Response:
        scheme, has_edge_scheme = original_scheme(request)
        request_host = request.headers.get("host", "").split(":", 1)[0].lower()
        if scheme == "http" and (
            has_edge_scheme or request_host == configured.public_host
        ):
            destination = f"https://{configured.public_host}{request.url.path}"
            if request.url.query:
                destination += f"?{request.url.query}"
            return secure(RedirectResponse(destination, status_code=308))
        return secure(await call_next(request))

    @application.get("/healthz")
    async def healthz(request: Request) -> JSONResponse:
        try:
            account = runtime.accounts.get()
            upstream = await request.app.state.client.get(
                f"{configured.upstream}/healthz"
            )
            upstream_ok = upstream.status_code == 200
        except (OSError, sqlite3.Error, httpx.HTTPError):
            return JSONResponse({"status": "error"}, status_code=503)
        healthy = account is not None and upstream_ok
        return JSONResponse(
            {"status": "ok" if healthy else "error"},
            status_code=200 if healthy else 503,
        )

    @application.get("/login")
    async def login_get(request: Request) -> Response:
        if authenticated(request):
            return RedirectResponse(
                safe_next(request.query_params.get("next")),
                status_code=303,
            )
        return login_page(request)

    @application.post("/login")
    async def login_post(request: Request) -> Response:
        form = await request.form()
        submitted_csrf = str(form.get("csrf_token", ""))
        expected_csrf = str(request.session.get("csrf_token", ""))
        if not expected_csrf or not hmac.compare_digest(
            submitted_csrf,
            expected_csrf,
        ):
            return login_page(
                request,
                error="登入頁已失效，請重新整理後再試。",
                status_code=400,
            )

        key = client_key(request)
        if is_rate_limited(runtime.failures, key):
            return login_page(
                request,
                error="登入嘗試次數過多，請 15 分鐘後再試。",
                status_code=429,
            )

        supplied_username = str(form.get("username", ""))
        supplied_password = str(form.get("password", ""))
        try:
            account = runtime.accounts.get()
            valid = False
            if account:
                username, password_hash, session_version = account
                username_valid = hmac.compare_digest(supplied_username, username)
                try:
                    password_valid = PASSWORD_HASHER.verify(
                        password_hash,
                        supplied_password,
                    )
                except (InvalidHashError, VerificationError, VerifyMismatchError):
                    password_valid = False
                valid = bool(username_valid and password_valid)
            if not account or not valid:
                record_failure(runtime.failures, key)
                return login_page(
                    request,
                    error="帳號或密碼不正確。",
                    status_code=401,
                )
        except (OSError, sqlite3.Error):
            return login_page(
                request,
                error="登入服務暫時無法使用，請稍後再試。",
                status_code=503,
            )

        runtime.failures.pop(key, None)
        request.session.clear()
        request.session.update(
            username=username,
            session_version=session_version,
            csrf_token=secrets.token_urlsafe(32),
        )
        return secure(
            RedirectResponse(
                safe_next(request.query_params.get("next")),
                status_code=303,
            )
        )

    @application.get("/logout")
    async def logout(request: Request) -> Response:
        request.session.clear()
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(
            COOKIE_NAME,
            path="/",
            secure=True,
            httponly=True,
            samesite="lax",
        )
        return secure(response)

    @application.api_route("/{path:path}", methods=["GET", "HEAD"])
    async def proxy(request: Request, path: str) -> Response:
        if not authenticated(request):
            destination = request.url.path
            if request.url.query:
                destination += f"?{request.url.query}"
            return secure(
                RedirectResponse(
                    f"/login?next={quote(destination, safe='/')}",
                    status_code=303,
                )
            )

        upstream_url = f"{configured.upstream}/{path}"
        if request.url.query:
            upstream_url += f"?{request.url.query}"
        headers = {
            name: value
            for name, value in request.headers.items()
            if name.lower() not in HOP_BY_HOP_HEADERS
            and name.lower() not in UNTRUSTED_PROXY_HEADERS
            and name.lower() not in {"cookie", "host"}
        }
        headers.update(
            {
                "accept-encoding": "identity",
                "host": configured.public_host,
                "x-forwarded-proto": "https",
            }
        )
        try:
            upstream_response = await request.app.state.client.request(
                request.method,
                upstream_url,
                headers=headers,
            )
        except httpx.HTTPError:
            return secure(
                JSONResponse(
                    {"detail": "Dashboard origin is temporarily unavailable."},
                    status_code=503,
                )
            )
        response_headers = {
            name: value
            for name, value in upstream_response.headers.items()
            if name.lower() not in HOP_BY_HOP_HEADERS and name.lower() != "set-cookie"
        }
        return secure(
            Response(
                upstream_response.content,
                status_code=upstream_response.status_code,
                headers=response_headers,
            )
        )

    return application
