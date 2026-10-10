"""OIDC single sign-on (Entra ID or generic provider): Authorization Code + PKCE."""
from __future__ import annotations

import logging
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from tls_scan_app.api.auth import open_session
from tls_scan_app.auth import flow_cookie, oidc
from tls_scan_app.deps import client_ip, get_db
from tls_scan_app.models import Role, User
from tls_scan_app.services import audit
from tls_scan_app.services.logs import scrub_text

router = APIRouter(prefix="/api/auth", tags=["sso"])
logger = logging.getLogger("tls_scan_app.sso")


def _redirect_uri(request: Request) -> str:
    return request.app.state.settings.public_base_url.rstrip("/") + "/api/auth/sso/callback"


@router.get("/providers")
def providers(request: Request) -> dict:
    s = request.app.state.settings
    return {"local": True, "crashtest": s.crashtest, "sso": {"enabled": bool(s.oidc_issuer), "provider": s.oidc_provider or "generic"} if s.oidc_issuer else {"enabled": False}}


@router.get("/sso/login")
async def sso_login(request: Request):
    s = request.app.state.settings
    if not (s.oidc_issuer and s.oidc_client_id):
        raise HTTPException(404, "SSO is not configured")
    try:
        metadata = await oidc.discover_provider(s.oidc_issuer)
    except Exception as error:  # noqa: BLE001 - diagnostics are logged, the browser gets a generic error
        logger.error("sso discovery failed: %s", scrub_text(str(error)))
        raise HTTPException(502, "The identity provider is unreachable") from error
    req = oidc.build_authorization_request(metadata, client_id=s.oidc_client_id, redirect_uri=_redirect_uri(request))
    response = RedirectResponse(req.url, status_code=302)
    response.set_cookie(
        flow_cookie.LOGIN_FLOW_COOKIE,
        flow_cookie.sign({"state": req.state, "nonce": req.nonce, "code_verifier": req.code_verifier}, s.session_secret),
        max_age=flow_cookie.MAX_AGE_SECONDS, httponly=True, secure=s.cookie_secure, samesite="lax", path="/api/auth",
    )
    return response


@router.get("/sso/callback")
async def sso_callback(request: Request, code: str = Query(""), state: str = Query(""), db: DbSession = Depends(get_db)):
    s = request.app.state.settings
    flow = flow_cookie.verify(request.cookies.get(flow_cookie.LOGIN_FLOW_COOKIE, ""), s.session_secret)
    if not flow or flow.get("state") != state or not code:
        raise HTTPException(400, "Invalid login state")

    async def fail(reason: str, detail: str):
        audit.record(db, "auth.sso_login", actor_label="sso", outcome="failure", detail={"reason": reason, "detail": scrub_text(detail)[:300]}, ip_address=client_ip(request))
        db.commit()
        logger.warning("sso login failed reason=%s detail=%s", reason, scrub_text(detail)[:300])
        raise HTTPException(400, "Sign-in failed")

    try:
        metadata = await oidc.discover_provider(s.oidc_issuer)
        claims = await oidc.exchange_code(
            metadata, code=code, redirect_uri=_redirect_uri(request), client_id=s.oidc_client_id,
            client_secret=s.oidc_client_secret, code_verifier=flow["code_verifier"], expected_nonce=flow["nonce"],
        )
    except oidc.OidcError as error:
        await fail("oidc_exchange_failed", str(error))
    except Exception as error:  # noqa: BLE001
        await fail("provider_unreachable", str(error))

    user = db.execute(select(User).where(User.issuer == claims.issuer, User.subject == claims.subject)).scalar_one_or_none()
    if user is None:
        user = User(issuer=claims.issuer, subject=claims.subject, email=claims.email.lower(), display_name=claims.name or claims.email,
                    role=Role(s.oidc_default_role))
        db.add(user)
        db.flush()
        audit.record(db, "user.sso_provisioned", actor=user, resource_type="user", resource_id=user.id, detail={"role": str(user.role)})
    else:
        user.email, user.display_name = claims.email.lower(), claims.name or user.display_name
    if not user.active:
        await fail("account_disabled", claims.email)
    response = RedirectResponse("/", status_code=302)
    open_session(db, request, response, user)
    response.delete_cookie(flow_cookie.LOGIN_FLOW_COOKIE, path="/api/auth")
    audit.record(db, "auth.sso_login", actor=user, ip_address=client_ip(request))
    db.commit()
    return response
