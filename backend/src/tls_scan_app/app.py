from __future__ import annotations

import logging
import uuid
from collections.abc import Callable

from fastapi import FastAPI, Request, Response

from tls_scan_app.api import admin, auth, catalog, definitions, health, policies, results, runs, sso, swagger
from tls_scan_app.config import Settings, get_settings
from tls_scan_app.database import make_engine, make_session_factory
from tls_scan_app.services.bootstrap import ensure_bootstrap
from tls_scan_app.services.logs import configure_logging
from tls_scan_app.services.rate_limit import SlidingWindowLimiter

logger = logging.getLogger("tls_scan_app.api")

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cache-Control": "no-store",
}


def make_app(settings: Settings | None = None, bootstrap: bool = True) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings, "api")
    # The only API documentation is the read-only results one (/swagger, authenticated); the full internal schema is not published.
    app = FastAPI(title="TLS Scan", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.state.engine = make_engine(settings.database_url)
    app.state.session_factory = make_session_factory(app.state.engine)
    app.state.limiter = SlidingWindowLimiter()

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Callable) -> Response:
        request_id = uuid.uuid4().hex[:12]
        response = await call_next(request)
        for key, value in SECURITY_HEADERS.items():
            response.headers.setdefault(key, value)
        response.headers["X-Request-ID"] = request_id
        return response

    for module in (health, auth, sso, catalog, policies, definitions, runs, admin, results, swagger):
        app.include_router(module.router)

    if bootstrap:
        with app.state.session_factory() as db:
            ensure_bootstrap(db, settings)
    return app


def create_app() -> FastAPI:  # uvicorn --factory tls_scan_app.app:create_app
    return make_app()
