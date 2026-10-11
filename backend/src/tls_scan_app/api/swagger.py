"""Swagger UI for the read-only results API, served locally and behind the same session as the rest of the app.

`/swagger` and `/swagger/` both answer directly (no redirect). The OpenAPI document is generated from the results
router only, so internal operations (launch, cancel, delete, admin...) are never described.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.openapi.utils import get_openapi
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

from tls_scan_app.api.results import router as results_router
from tls_scan_app.auth.tokens import SESSION_COOKIE
from tls_scan_app.deps import require_role
from tls_scan_app.models import Role

STATIC = Path(__file__).resolve().parent.parent / "static" / "swagger"
ASSETS = {"swagger-ui.css": "text/css", "swagger-ui-bundle.js": "application/javascript", "favicon-32x32.png": "image/png"}
# Everything is served from the same origin: no CDN, no inline script.
CSP = ("default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; "
       "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")

router = APIRouter(include_in_schema=False)
viewer = require_role(Role.AUDITOR)

DESCRIPTION = """Read-only access to TLS Scan results: scans, TLS endpoints, certificates, findings, comparisons and reports.

**Authentication (V1)**: the session of the logged-in user. Sign in to TLS Scan in the same browser, then use *Try it out*; the session
cookie is sent automatically. There are no API keys in this version. Only GET operations exist.

**Roles**: AUDITOR, USER, OPERATOR and ADMIN can consult scans, endpoints, findings and reports. Comparison requires USER or higher.

**Conventions**: dates are ISO 8601; a value that was not collected is `null` (never guessed); lists are paginated (`limit` 1-200, `offset`).
"""

INDEX = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>TLS Scan API</title><link rel="stylesheet" href="/swagger/swagger-ui.css"><link rel="icon" href="/swagger/favicon-32x32.png"></head>
<body><div id="swagger-ui"></div><script src="/swagger/swagger-ui-bundle.js"></script><script src="/swagger/init.js"></script></body></html>
"""
INIT_JS = """window.ui = SwaggerUIBundle({
  url: "/swagger/openapi.json",
  dom_id: "#swagger-ui",
  deepLinking: true,
  tryItOutEnabled: true,
  supportedSubmitMethods: ["get"],
  requestInterceptor: function (req) { req.credentials = "same-origin"; return req; }
});
"""


def build_openapi(app_version: str = "1.0.0") -> dict:
    schema = get_openapi(title="TLS Scan - Results API", version=app_version, description=DESCRIPTION, routes=results_router.routes,
                         servers=[{"url": "/"}])
    schema.setdefault("components", {})["securitySchemes"] = {
        "sessionCookie": {"type": "apiKey", "in": "cookie", "name": SESSION_COOKIE,
                          "description": "Session cookie set when you sign in to TLS Scan; sent automatically by the browser."}}
    schema["security"] = [{"sessionCookie": []}]
    return schema


def _page(content: str, media: str) -> HTMLResponse:
    return HTMLResponse(content, media_type=media, headers={"Content-Security-Policy": CSP, "Cache-Control": "no-store"})


@router.get("/swagger")
@router.get("/swagger/")
def swagger_ui(user=Depends(viewer)) -> HTMLResponse:
    return _page(INDEX, "text/html")


@router.get("/swagger/openapi.json")
def swagger_schema(request: Request, user=Depends(viewer)) -> JSONResponse:
    if not hasattr(request.app.state, "results_openapi"):
        request.app.state.results_openapi = build_openapi()
    return JSONResponse(request.app.state.results_openapi, headers={"Cache-Control": "no-store"})


@router.get("/swagger/init.js")
def swagger_init(user=Depends(viewer)) -> HTMLResponse:
    return _page(INIT_JS, "application/javascript")


@router.get("/swagger/{asset}")
def swagger_asset(asset: str, user=Depends(viewer)) -> FileResponse:
    if asset not in ASSETS:
        raise HTTPException(404, "Not found")
    return FileResponse(STATIC / asset, media_type=ASSETS[asset], headers={"Cache-Control": "private, max-age=3600"})
