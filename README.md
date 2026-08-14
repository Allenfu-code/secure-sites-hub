# Secure Sites Hub

A security-conscious, read-only operations dashboard for self-hosted websites,
APIs, systemd services, containers, and Cloudflare Tunnel deployments.

The public repository is a sanitized reference implementation. It starts with a
synthetic registry, disables host discovery and internal probes by default, and
returns an allowlisted public view that omits filesystem paths, unit names,
ports, probe targets, notes, and discovery candidates.

> 中文摘要：這是我的自架服務唯讀管理中心。公開版本只使用合成資料；正式
> 清冊、內部路徑、服務拓撲、登入資料庫、歷史資料與 Tunnel 憑證永不進入
> GitHub。

## Why this project exists

Running multiple side projects across Windows, WSL, Docker, systemd, and
Cloudflare quickly creates an observability problem. Secure Sites Hub provides
one read-only view of availability, component health, lifecycle state, and
90-day history without adding deployment, shell, restart, or write controls.

The private production instance is available at
[`sites.allenfuhome.com`](https://sites.allenfuhome.com) and requires
authentication. No public demo credentials are provided.

## Security-first architecture

```text
Browser
  -> HTTPS / Cloudflare Tunnel
  -> authentication gateway
       CSRF + Argon2 + throttling + secure session cookie
  -> loopback-only FastAPI origin
       read-only routes + public DTO allowlist
  -> private registry and owner-only SQLite history
```

Key controls:

- GET/HEAD-only dashboard surface; no deploy, restart, shell, or mutation API.
- Origin and gateway are designed to bind to `127.0.0.1` only.
- Exact HTTPS redirect, CSP, HSTS, no-store responses, and proxy-header
  filtering at the gateway.
- Session-version checks invalidate existing sessions after an account change.
- Session secrets, account cache, registry, and history remain outside Git.
- Owner/type/link-count and `0700`/`0600` checks fail closed on unsafe private
  storage.
- Public mode hides internal targets and disables discovery and local probes.
- HTTP probes reject URL credentials and non-global destinations by default.
- The active Tunnel configuration ends with `http_status:404`.

## Safe defaults

| Setting | Default | Effect |
| --- | --- | --- |
| `SITES_HUB_REGISTRY` | `sites.example.yaml` | Uses synthetic data only. |
| `SITES_HUB_DISCOVERY_ENABLED` | `false` | Does not enumerate host projects, services, containers, or tunnels. |
| `SITES_HUB_PROBES_ENABLED` | `false` | Does not run local system probes. |
| `SITES_HUB_EXPOSE_INTERNALS` | `false` | Omits source paths, targets, details, notes, and candidates. |
| `SITES_HUB_ALLOW_PRIVATE_HTTP` | `false` | Blocks loopback, private, link-local, reserved, and metadata destinations. |
| `CLOUDFLARE_ACCESS_REQUIRED` | `false` | Optional only; the separate login gateway is the documented private boundary. |

Production operators must opt in deliberately and keep every corresponding
configuration file private. Enabling internal details does not make them safe
to expose publicly.

## Local synthetic demo

Requirements: Python 3.11+ and [`uv`](https://docs.astral.sh/uv/).

```bash
uv sync --locked --group dev
uv run uvicorn app.main:app --host 127.0.0.1 --port 9620
```

Open `http://127.0.0.1:9620`. The example registry contains only reserved
example names and synthetic paths. To run the automated smoke test:

```bash
./scripts/smoke_test.sh
```

## Authentication gateway

The generic gateway expects a private SQLite database containing one
`admin_account(username, password_hash, session_version)` row. Passwords are
verified with Argon2; plaintext passwords are never stored by this project.

Create or provide the database outside the repository, set the environment
variables shown in [`examples/deploy/sites-hub.env.example`](examples/deploy/sites-hub.env.example),
and run the ASGI factory:

```bash
uv run uvicorn --factory app.auth_gateway:create_app \
  --host 127.0.0.1 --port 9621 --no-proxy-headers
```

The gateway generates an owner-only session secret on first start when the
configured file is absent. It refuses unsafe symlinks, multi-link files,
incorrect ownership, or filesystems that do not preserve POSIX permissions.

## Production boundary

This repository intentionally does **not** contain:

- the production `sites.yaml` registry;
- absolute source paths, unit names, container names, or internal ports;
- authentication databases, password hashes, sessions, or account caches;
- history databases, logs, backups, or discovered candidates;
- active Tunnel UUIDs, credential files, DNS configuration, or runtime units.

Generic deployment examples live under [`examples/deploy/`](examples/deploy/).
They are templates, not a copy of the live deployment. A real deployment should
use a dedicated OS user or otherwise account for the sandbox limitations of
user-level systemd on older hosts.

## Verification

The GitHub Actions workflow runs on GitHub-hosted runners only and uses:

- the locked dependency graph;
- Python 3.11 and 3.13;
- Ruff, bytecode compilation, and the full offline test suite;
- a synthetic HTTP smoke test, complete dependency vulnerability audit, and
  full-history secret scan.

Tests use temporary secrets, synthetic SQLite accounts, and synthetic registry
fixtures. They do not read a production registry or runtime credential.

## Limitations

- This is a single-operator dashboard, not a multi-tenant monitoring platform.
- In-memory login throttling should be paired with an edge rate-limit rule for
  higher-risk deployments.
- Registry entries are trusted operator configuration. Private HTTP probing
  must remain disabled unless its destinations are tightly controlled.
- Public screenshots and demos must use synthetic data only.

## License

MIT. See [LICENSE](LICENSE).
