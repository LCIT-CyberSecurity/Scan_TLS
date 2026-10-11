"""The signed-in user's own external access (REST API key and MCP key): state, generate, revoke.

Session-authenticated like the rest of the WebUI. The secret is returned once by the generating call only.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session as DbSession

from tls_scan_app.deps import client_ip, get_db, get_current_user
from tls_scan_app.models import User
from tls_scan_app.services import audit, external_access

router = APIRouter(prefix="/api/me/access", tags=["access"])


def _state(db: DbSession, user: User, service: str) -> dict:
    allowed = bool(user.api_access_enabled if service == "api" else user.mcp_access_enabled)
    return {"global_enabled": external_access.service_enabled(db, service), "allowed": allowed,
            "key": external_access.token_summary(db, user.id, service)}


@router.get("")
def my_access(db: DbSession = Depends(get_db), user: User = Depends(get_current_user)) -> dict:
    return {service: _state(db, user, service) for service in external_access.SERVICES}


def _service(service: str) -> str:
    if service not in external_access.SERVICES:
        raise HTTPException(404, "Unknown service")
    return service


@router.post("/{service}/token", status_code=201)
def generate_key(service: str, request: Request, db: DbSession = Depends(get_db), user: User = Depends(get_current_user)) -> dict:
    service = _service(service)
    if user.must_change_password:
        raise HTTPException(403, "Password change required")
    try:
        created = external_access.create_token(db, user, service)
    except external_access.AccessUnavailable as error:
        audit.record(db, f"external_access.{service}_key_refused", actor=user, resource_type="user", resource_id=user.id,
                     outcome="failure", detail={"reason": str(error)}, ip_address=client_ip(request))
        db.commit()
        raise HTTPException(403, str(error)) from None
    audit.record(db, f"external_access.{service}_key_created", actor=user, resource_type="user", resource_id=user.id,
                 detail={"prefix": created["prefix"], "expires_at": str(created["expires_at"])}, ip_address=client_ip(request))
    db.commit()
    return created


@router.delete("/{service}/token", status_code=204)
def revoke_key(service: str, request: Request, db: DbSession = Depends(get_db), user: User = Depends(get_current_user)) -> None:
    service = _service(service)
    revoked = external_access.revoke_tokens(db, user.id, service)
    audit.record(db, f"external_access.{service}_key_revoked", actor=user, resource_type="user", resource_id=user.id,
                 detail={"revoked": revoked, "by": "owner"}, ip_address=client_ip(request))
    db.commit()
