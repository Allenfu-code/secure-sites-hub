# Security policy

## Supported version

Security fixes are applied to the latest commit on `main`.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository. Do not open
a public issue containing credentials, session material, private hostnames,
filesystem paths, internal targets, account data, or exploit details.

## Public repository boundary

This repository is a sanitized reference implementation. Never commit a
production registry, discovery output, runtime environment, authentication
database, session secret, account cache, history database, active Tunnel
configuration, logs, backups, or screenshots of real infrastructure.

The example registry and tests must remain synthetic. CI must use GitHub-hosted
runners and temporary directories; it must never run in a production service
directory or on a runner that can access production credentials.

## Deployment baseline

- Bind both origin and authentication gateway to loopback.
- Route the Tunnel to the gateway, never directly to the dashboard origin.
- Keep the final Tunnel ingress rule as `http_status:404`.
- Use HTTPS, Secure/HttpOnly/SameSite cookies, CSRF validation, Argon2, session
  version checks, bounded throttling, restrictive response headers, and
  no-store caching.
- Keep private files on a POSIX filesystem that enforces `0700`/`0600` modes.
- Leave discovery, local probes, internal DTO fields, and private HTTP probing
  disabled unless a private deployment explicitly requires them.
- Treat the registry as trusted configuration and review every outbound URL.
- Prefer a dedicated service account and least-privilege filesystem access.

## Incident response

If sensitive material reaches GitHub, revoke or rotate it first. Then remove it
from complete Git history and coordinate cleanup of forks, pull requests,
caches, and clones. Deleting only the current file is not sufficient.
