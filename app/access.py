from __future__ import annotations

import asyncio
import os
import time
from typing import Any

import httpx
import jwt
from fastapi import HTTPException, Request


class CloudflareAccessVerifier:
    """Fail-closed verification for Cloudflare Access JWT assertions."""

    def __init__(self) -> None:
        self.required = os.getenv("CLOUDFLARE_ACCESS_REQUIRED", "false").lower() in {
            "1",
            "true",
            "yes",
        }
        self.team_domain = os.getenv("CF_ACCESS_TEAM_DOMAIN", "").strip().rstrip("/")
        self.audience = os.getenv("CF_ACCESS_AUD", "").strip()
        self._jwks: dict[str, Any] | None = None
        self._jwks_at = 0.0
        self._lock = asyncio.Lock()

    async def verify(self, request: Request) -> None:
        if not self.required:
            return
        if request.url.path == "/healthz":
            return
        if not self.team_domain or not self.audience:
            raise HTTPException(status_code=503, detail="Access 尚未設定完成")
        token = request.headers.get("cf-access-jwt-assertion", "")
        if not token:
            raise HTTPException(status_code=403, detail="需要 Cloudflare Access")
        jwks = await self._get_jwks()
        try:
            header = jwt.get_unverified_header(token)
            key_data = next(
                key for key in jwks.get("keys", []) if key.get("kid") == header["kid"]
            )
            key = jwt.PyJWK.from_dict(key_data).key
            jwt.decode(
                token,
                key=key,
                algorithms=["RS256"],
                audience=self.audience,
                issuer=f"https://{self.team_domain}",
            )
        except (jwt.PyJWTError, KeyError, StopIteration, ValueError):
            raise HTTPException(status_code=403, detail="Access 憑證無效")

    async def _get_jwks(self) -> dict[str, Any]:
        if self._jwks and time.monotonic() - self._jwks_at < 3600:
            return self._jwks
        async with self._lock:
            if self._jwks and time.monotonic() - self._jwks_at < 3600:
                return self._jwks
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    response = await client.get(
                        f"https://{self.team_domain}/cdn-cgi/access/certs"
                    )
                    response.raise_for_status()
                    self._jwks = response.json()
                    self._jwks_at = time.monotonic()
                    return self._jwks
            except (httpx.HTTPError, ValueError):
                raise HTTPException(
                    status_code=503, detail="無法驗證 Cloudflare Access"
                )
