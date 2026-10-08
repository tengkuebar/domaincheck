from __future__ import annotations

import secrets
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.checks import engine
from app.config import Settings
from app.dns import DnsResolver, Resolver
from app.scanning.service import JobRunner, Runner, default_runner
from app.scanning.store import ResultStore
from app.web import routes
from app.web.middleware import SessionAndHeadersMiddleware
from app.web.ratelimit import Limiters
from app.web.render import render
from app.web.security import SessionCodec

_ERROR_TITLES = {
    403: "Request refused",
    404: "Not found",
    429: "Too many requests",
    503: "Busy",
}


def create_app(
    settings: Settings | None = None,
    resolver: Resolver | None = None,
    scan_runner: Runner = default_runner,
    sync_jobs: bool = False,
) -> FastAPI:
    settings = settings or Settings()
    engine.set_path_check_enabled(settings.enable_path_check)
    app = FastAPI(title="DomainCheck", docs_url=None, redoc_url=None, openapi_url=None)

    app.state.settings = settings
    app.state.resolver = resolver or DnsResolver()
    app.state.limiters = Limiters(
        settings.limit_ip_per_hour, settings.limit_domain_per_hour, settings.limit_global_per_hour
    )
    app.state.store = ResultStore()
    app.state.jobs = JobRunner(
        app.state.store, app.state.resolver, scan_runner, synchronous=sync_jobs
    )

    codec = SessionCodec(
        settings.secret_key or secrets.token_urlsafe(48), settings.session_ttl_seconds
    )
    app.add_middleware(
        SessionAndHeadersMiddleware,
        codec=codec,
        secure_cookies=settings.secure_cookies,
        hsts=settings.hsts,
    )
    app.mount(
        "/static", StaticFiles(directory=Path(__file__).parent / "web" / "static"), name="static"
    )
    app.include_router(routes.router)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        location = (exc.headers or {}).get("Location")
        if exc.status_code == 303 and location:
            return RedirectResponse(location, status_code=303)
        title = _ERROR_TITLES.get(exc.status_code, "Something went wrong")
        return render(request, "error.html", exc.status_code, title=title, message=str(exc.detail))

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app
