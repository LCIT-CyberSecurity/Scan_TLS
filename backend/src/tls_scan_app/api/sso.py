"""External sign-in: OIDC (Microsoft Entra ID, Google Workspace, generic) with Authorization Code + PKCE, and LDAP.

One mechanism for every OIDC provider (state, nonce, PKCE S256, signature / issuer / audience / dates); the provider only adds
its own restriction afterwards: the Entra tenant, or the Google Workspace domain. Sessions, CSRF, roles and audit are the
application's own: nothing here creates a second session system.
"""
from __future__ import annotations

import logging
import re

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session as DbSession

from tls_scan_app.api.auth import open_session, user_payload
from tls_scan_app.auth import flow_cookie, oidc
from tls_scan_app.auth.diagnostics import explain
from tls_scan_app.connectors import ldap_auth
from tls_scan_app.deps import client_ip, get_db
from tls_scan_app.services import audit, auth_config
from tls_scan_app.services.identity import External, SignInRefused, resolve
from tls_scan_app.services.logs import scrub_text

router = APIRouter(prefix="/api/auth", tags=["sso"])
logger = logging.getLogger("tls_scan_app.sso")
GUID = re.compile(r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")


def redirect_uri(request: Request) -> str:
    return request.app.state.settings.public_base_url.rstrip("/") + "/api/auth/sso/callback"


def _blocked(request: Request, key: str, limit: int = 30) -> bool:
    settings, limiter = request.app.state.settings, request.app.state.limiter
    return settings.rate_limit_enabled and limiter.count(key, 300) >= limit


@router.get("/providers")
def providers(request: Request, db: DbSession = Depends(get_db)) -> dict:
    cfg = auth_config.effective(db, request.app.state.settings)
    return {"local": True, "crashtest": request.app.state.settings.crashtest,
            "sso": {"enabled": cfg.oidc, "provider": cfg.provider} if cfg.oidc else {"enabled": False},
            "ldap": {"enabled": cfg.ldap_enabled, "name": cfg.ldap.get("name", "")} if cfg.ldap_enabled else {"enabled": False}}


@router.get("/sso/login")
async def sso_login(request: Request, db: DbSession = Depends(get_db)):
    s = request.app.state.settings
    cfg = auth_config.effective(db, s)
    if not cfg.oidc:
        raise HTTPException(404, "SSO is not configured")
    try:
        metadata = await oidc.discover_provider(cfg.issuer)
    except Exception as error:  # noqa: BLE001 - diagnostics are logged, the browser gets a generic error
        logger.error("sso discovery failed: %s", scrub_text(str(error)))
        audit.record(db, "auth.sso_login", actor_label=cfg.provider, outcome="failure", detail={"reason": "discovery", **explain("discovery"), "detail": scrub_text(str(error))[:200]}, ip_address=client_ip(request))
        db.commit()
        raise HTTPException(502, "The identity provider is unreachable") from error
    extra = {"hd": cfg.allowed_domains[0]} if cfg.provider == "google" and len(cfg.allowed_domains) == 1 else None   # a hint only: the signed claim is what is checked
    req = oidc.build_authorization_request(metadata, client_id=cfg.client_id, redirect_uri=redirect_uri(request), extra_params=extra)
    response = RedirectResponse(req.url, status_code=302)
    response.set_cookie(
        flow_cookie.LOGIN_FLOW_COOKIE,
        flow_cookie.sign({"state": req.state, "nonce": req.nonce, "code_verifier": req.code_verifier}, s.session_secret),
        max_age=flow_cookie.MAX_AGE_SECONDS, httponly=True, secure=s.cookie_secure, samesite="lax", path="/api/auth",
    )
    return response


def _provider_rules(cfg: auth_config.Effective, claims: oidc.IdentityClaims, issuer: str) -> None:
    """The restriction each provider adds on top of the generic ID-token validation. Raises oidc.OidcError."""
    if cfg.provider == "entra" and cfg.tenant_id:
        expected = cfg.tenant_id if GUID.match(cfg.tenant_id) else next((p for p in issuer.split("/") if GUID.match(p)), "")
        tid = str(claims.extra.get("tid", ""))
        if not expected or tid.lower() != expected.lower():
            raise oidc.OidcError("tenant mismatch: the token does not come from the configured tenant")
    if cfg.provider == "google":
        hd = str(claims.extra.get("hd", "")).lower()
        if not hd or hd not in cfg.allowed_domains:
            raise oidc.OidcError("workspace domain: the account is not in an allowed Google Workspace domain")
        if claims.extra.get("email_verified") is not True:
            raise oidc.OidcError("workspace domain: the e-mail address is not verified by Google")


@router.get("/sso/callback")
async def sso_callback(request: Request, code: str = Query(""), state: str = Query(""), error: str = Query(""), db: DbSession = Depends(get_db)):
    s = request.app.state.settings
    cfg = auth_config.effective(db, s)
    ip = client_ip(request)
    if not cfg.oidc:
        raise HTTPException(404, "SSO is not configured")
    flow = flow_cookie.verify(request.cookies.get(flow_cookie.LOGIN_FLOW_COOKIE, ""), s.session_secret)
    if _blocked(request, f"sso:ip:{ip}"):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts, try again later")

    async def fail(reason: str, detail: str):
        request.app.state.limiter.hit(f"sso:ip:{ip}")
        info = explain(f"{reason} {detail}", redirect=redirect_uri(request))
        audit.record(db, "auth.sso_login", actor_label=cfg.provider or "sso", outcome="failure",
                     detail={"reason": reason, "code": info["code"], "detail": scrub_text(detail)[:300]}, ip_address=ip)
        db.commit()
        logger.warning("sso login failed provider=%s reason=%s code=%s detail=%s", cfg.provider, reason, info["code"], scrub_text(detail)[:300])
        raise HTTPException(400, "Sign-in failed")

    if error:   # the provider itself refused (e.g. access_denied, AADSTS error in error_description): log the code, never echo it
        await fail("provider_error", f"{error} {request.query_params.get('error_description', '')}")
    if not flow or flow.get("state") != state or not code:
        await fail("invalid_state", "state or flow cookie missing / altered")
    try:
        metadata = await oidc.discover_provider(cfg.issuer)
        claims = await oidc.exchange_code(
            metadata, code=code, redirect_uri=redirect_uri(request), client_id=cfg.client_id,
            client_secret=cfg.client_secret, code_verifier=flow["code_verifier"], expected_nonce=flow["nonce"],
        )
        _provider_rules(cfg, claims, metadata.issuer)
    except oidc.OidcError as exc:
        await fail("oidc_exchange_failed", str(exc))
    except Exception as exc:  # noqa: BLE001
        await fail("provider_unreachable", str(exc))

    try:
        user = resolve(db, External(claims.issuer, claims.subject, claims.email, claims.name), auto_provision=cfg.auto_provision, default_role=cfg.default_role)
    except SignInRefused as refused:
        await fail(refused.reason, refused.detail)
    response = RedirectResponse("/", status_code=302)
    open_session(db, request, response, user)
    response.delete_cookie(flow_cookie.LOGIN_FLOW_COOKIE, path="/api/auth")
    audit.record(db, "auth.sso_login", actor=user, ip_address=ip, detail={"provider": cfg.provider})
    db.commit()
    return response


class LdapLoginBody(BaseModel):
    username: str
    password: str


@router.post("/ldap/login")
def ldap_login(body: LdapLoginBody, request: Request, response: Response, db: DbSession = Depends(get_db)) -> dict:
    s, limiter, ip = request.app.state.settings, request.app.state.limiter, client_ip(request)
    cfg = auth_config.effective(db, s)
    if not cfg.ldap_enabled:
        raise HTTPException(404, "LDAP sign-in is not configured")
    name = "".join(c for c in body.username.strip().lower() if c.isprintable())[:256]   # control characters never reach the audit log or a limiter key
    if s.rate_limit_enabled and (limiter.count(f"login:ip:{ip}", 300) >= 20 or limiter.count(f"login:user:{name}", 300) >= 5):
        audit.record(db, "auth.ldap_login", actor_label=name, outcome="blocked", ip_address=ip)
        db.commit()
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts, try again later")

    def refuse(reason: str, detail: str = "") -> HTTPException:
        limiter.hit(f"login:ip:{ip}")
        limiter.hit(f"login:user:{name}")
        info = explain(reason)
        audit.record(db, "auth.ldap_login", actor_label=name, outcome="failure", detail={"reason": reason, "code": info["code"], "detail": scrub_text(detail)[:200]}, ip_address=ip)
        db.commit()
        logger.warning("ldap login failed reason=%s", reason)
        return HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")   # the same answer whatever the cause: no account probing

    try:
        who = ldap_auth.authenticate(cfg.ldap, cfg.ldap_password, body.username, body.password)
    except ldap_auth.LdapAuthError as error:
        raise refuse(error.code, error.message) from error
    if not who.email:
        raise refuse("no_email", "the directory entry has no e-mail attribute")
    try:
        user = resolve(db, External(ldap_auth.issuer_for(cfg.ldap), who.subject, who.email, who.name), auto_provision=cfg.auto_provision, default_role=cfg.default_role)
    except SignInRefused as refused:
        raise refuse(refused.reason, refused.detail) from refused
    limiter.reset(f"login:user:{name}")
    session = open_session(db, request, response, user)
    audit.record(db, "auth.ldap_login", actor=user, ip_address=ip)
    db.commit()
    return {"user": user_payload(user), "csrf_token": session.csrf_token}
