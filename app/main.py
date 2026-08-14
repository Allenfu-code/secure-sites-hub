from __future__ import annotations

import os
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .access import CloudflareAccessVerifier
from .service import SitesHubService

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("SITES_HUB_DATA_DIR", str(BASE_DIR / "data")))
REGISTRY_PATH = Path(
    os.getenv("SITES_HUB_REGISTRY", str(BASE_DIR / "sites.example.yaml"))
)

service = SitesHubService(
    registry_path=REGISTRY_PATH,
    database_path=DATA_DIR / "history.sqlite3",
    windows_probe_script=BASE_DIR / "scripts" / "windows_probe.ps1",
)
access_verifier = CloudflareAccessVerifier()
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@asynccontextmanager
async def lifespan(_: FastAPI):
    await service.start()
    yield
    await service.stop()


app = FastAPI(
    title="AllenFu 網站總控中心",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


@app.middleware("http")
async def security_and_access(request: Request, call_next):
    try:
        await access_verifier.verify(request)
    except HTTPException as exc:
        response = JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
            headers=exc.headers,
        )
    else:
        response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), payment=()"
    )
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; script-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
        "base-uri 'self'; form-action 'self'"
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/healthz")
async def healthz():
    return {
        "status": "ok",
        "sites": len(service.current),
        "generated_at": datetime.now(UTC).isoformat(),
    }


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "sites": service.sites(),
            "summary": service.summary(),
            "generated_at": datetime.now(UTC).isoformat(),
            "categories": service.categories(),
            "candidates": service.candidates(),
        },
    )


@app.get("/sites/{site_id}", response_class=HTMLResponse)
async def site_detail(request: Request, site_id: str):
    site = service.site(site_id)
    if not site:
        raise HTTPException(status_code=404, detail="找不到網站")
    return templates.TemplateResponse(
        request=request,
        name="site.html",
        context={
            "site": site,
            "history": service.history.daily_history(site_id, 90),
            "generated_at": datetime.now(UTC).isoformat(),
        },
    )


@app.get("/api/v1/summary")
async def api_summary():
    return {
        **service.summary(),
        "generated_at": datetime.now(UTC).isoformat(),
    }


@app.get("/api/v1/sites")
async def api_sites():
    return {
        "items": service.sites(),
        "generated_at": datetime.now(UTC).isoformat(),
    }


@app.get("/api/v1/sites/{site_id}")
async def api_site(site_id: str):
    site = service.site(site_id)
    if not site:
        raise HTTPException(status_code=404, detail="找不到網站")
    return {
        "item": site,
        "history": service.history.daily_history(site_id, 90),
        "generated_at": datetime.now(UTC).isoformat(),
    }


@app.get("/api/v1/candidates")
async def api_candidates():
    if not service.candidates_exposed:
        raise HTTPException(status_code=404, detail="找不到資源")
    return {
        "items": service.candidates(),
        "generated_at": datetime.now(UTC).isoformat(),
    }
