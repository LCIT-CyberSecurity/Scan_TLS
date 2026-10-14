"""Administration: users and roles, audit log, system settings, diagnostics."""
from __future__ import annotations

import secrets
import shutil
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from tls_scan_app.api.auth import user_payload
from tls_scan_app.api.common import get_or_404
from tls_scan_app.auth.passwords import hash_password
from tls_scan_app.database import database_is_ready
from tls_scan_app.deps import get_db, require_role
from tls_scan_app.models import AuditEvent, Role, ScanRun, Session, SystemSetting, User
from tls_scan_app.models.scan import ACTIVE_STATUSES
from tls_scan_app.services import audit, external_access
from tls_scan_app.services import auth_config
from tls_scan_app.services.identity import source_of

router = APIRouter(prefix="/api/admin", tags=["admin"])
admin_only = require_role(Role.ADMIN)

DEFAULT_SETTINGS = {
    "retention": {"reports_days": 365, "runs_days": 730, "audit_days": 1095},
    "dns_discovery": {"allowed_servers": [], "ct_enabled": True, "recent_scan_days": 7},
    "scan_exclusions": {"entries": []},  # never scanned, by any scan definition
    "notifications": {"connector": "none", "smtp": {"host": "", "port": 587, "starttls": True, "username": "", "from": ""},
                      "graph": {"tenant_id": "", "client_id": "", "sender": ""}},
}


class UserBody(BaseModel):
    email: EmailStr
    display_name: str = ""
    role: Role = Role.USER


class RoleBody(BaseModel):
    role: Role
    active: bool | None = None


@router.get("/users")
def list_users(db: DbSession = Depends(get_db), _: User = Depends(admin_only)) -> list[dict]:
    return [user_payload(u) | {"active": u.active, "issuer": u.issuer, "source": source_of(u.issuer), "last_login_at": u.last_login_at,
                               "access_keys": {s: external_access.token_summary(db, u.id, s) for s in external_access.SERVICES}}
            for u in db.execute(select(User).order_by(User.email)).scalars()]


@router.post("/users", status_code=201)
def create_user(body: UserBody, db: DbSession = Depends(get_db), actor: User = Depends(admin_only)) -> dict:
    """Create a local account with a one-time password (shown once); the user must change it at first login."""
    email = body.email.lower()
    if db.execute(select(User).where(func.lower(User.email) == email)).first():
        raise HTTPException(409, "A user with this e-mail already exists")
    temp = secrets.token_urlsafe(15)
    user = User(issuer="local:user", subject=email, email=email, display_name=body.display_name or email,
                password_hash=hash_password(temp), must_change_password=True, role=body.role)
    db.add(user)
    db.flush()
    audit.record(db, "user.create", actor=actor, resource_type="user", resource_id=user.id, detail={"email": email, "role": str(body.role)})
    db.commit()
    return {"user": user_payload(user), "temporary_password": temp}


@router.put("/users/{user_id}")
def update_user(user_id: uuid.UUID, body: RoleBody, db: DbSession = Depends(get_db), actor: User = Depends(admin_only)) -> dict:
    user = get_or_404(db, User, user_id, "User")
    admins = db.scalar(select(func.count()).select_from(User).where(User.role == Role.ADMIN, User.active.is_(True)))
    demoting = user.role == Role.ADMIN and (body.role != Role.ADMIN or body.active is False)
    if demoting and admins <= 1:
        raise HTTPException(409, "At least one active administrator is required")
    # The technical administrator signs in with a local password: it must survive a provider outage or a provider change.
    losing_local = (user.password_hash is not None and user.role == Role.ADMIN and user.active
                    and (body.role != Role.ADMIN or body.active is False))
    if losing_local and not db.scalar(select(func.count()).select_from(User).where(User.role == Role.ADMIN, User.active.is_(True), User.password_hash.is_not(None), User.id != user.id)):
        raise HTTPException(409, "At least one active local administrator (password sign-in) must remain: it is the emergency access when the external provider is down")
    previous = str(user.role)
    user.role = body.role
    if body.active is not None:
        user.active = body.active
        if not body.active:
            external_access.revoke_tokens(db, user.id)
            for s in db.execute(select(Session).where(Session.user_id == user.id, Session.revoked_at.is_(None))).scalars():
                s.revoked_at = datetime.now().astimezone()
    audit.record(db, "user.role_change", actor=actor, resource_type="user", resource_id=user.id,
                 detail={"from": previous, "to": str(body.role), "active": user.active})
    db.commit()
    return user_payload(user)


class AccessBody(BaseModel):
    api_access_enabled: bool | None = None
    mcp_access_enabled: bool | None = None


@router.put("/users/{user_id}/access")
def update_user_access(user_id: uuid.UUID, body: AccessBody, db: DbSession = Depends(get_db), actor: User = Depends(admin_only)) -> dict:
    """Allow or forbid the external REST API / MCP for a user (the keys are created by the user, never by an administrator)."""
    user = get_or_404(db, User, user_id, "User")
    external_access.set_user_access(db, user, actor, body.api_access_enabled, body.mcp_access_enabled)
    db.commit()
    return user_payload(user)


@router.delete("/users/{user_id}/access/{service}/token", status_code=204)
def revoke_user_key(user_id: uuid.UUID, service: str, db: DbSession = Depends(get_db), actor: User = Depends(admin_only)) -> None:
    if service not in external_access.SERVICES:
        raise HTTPException(404, "Unknown service")
    user = get_or_404(db, User, user_id, "User")
    revoked = external_access.revoke_tokens(db, user.id, service)
    audit.record(db, f"external_access.{service}_key_revoked", actor=actor, resource_type="user", resource_id=user.id, detail={"revoked": revoked, "by": "admin"})
    db.commit()


class ServiceBody(BaseModel):
    enabled: bool


@router.get("/external-access")
def get_external_access(db: DbSession = Depends(get_db), _: User = Depends(admin_only)) -> dict:
    return external_access.global_state(db)


@router.put("/external-access/{service}")
def set_external_access(service: str, body: ServiceBody, db: DbSession = Depends(get_db), actor: User = Depends(admin_only)) -> dict:
    """Global switch. Switching off suspends every key at once (they are not revoked); no restart needed."""
    if service not in external_access.SERVICES:
        raise HTTPException(404, "Unknown service")
    external_access.set_service_enabled(db, service, body.enabled, actor)
    db.commit()
    return external_access.global_state(db)


@router.post("/users/{user_id}/reset-password")
def reset_password(user_id: uuid.UUID, db: DbSession = Depends(get_db), actor: User = Depends(admin_only)) -> dict:
    user = get_or_404(db, User, user_id, "User")
    if user.password_hash is None:
        raise HTTPException(409, "This account signs in through SSO")
    temp = secrets.token_urlsafe(15)
    user.password_hash, user.must_change_password = hash_password(temp), True
    audit.record(db, "user.password_reset", actor=actor, resource_type="user", resource_id=user.id)
    db.commit()
    return {"temporary_password": temp}


@router.get("/audit")
def audit_log(action: str | None = None, actor: str | None = None, limit: int = 200, offset: int = 0,
              db: DbSession = Depends(get_db), _: User = Depends(admin_only)) -> list[dict]:
    stmt = select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(min(limit, 1000)).offset(offset)
    if action:
        stmt = stmt.where(AuditEvent.action.like(f"{action}%"))
    if actor:
        stmt = stmt.where(AuditEvent.actor_label.ilike(f"%{actor}%"))
    return [{"id": str(e.id), "created_at": e.created_at, "actor": e.actor_label, "action": e.action, "resource_type": e.resource_type,
             "resource_id": e.resource_id, "outcome": e.outcome, "detail": e.detail, "ip_address": e.ip_address}
            for e in db.execute(stmt).scalars()]


@router.get("/settings")
def get_settings_(db: DbSession = Depends(get_db), _: User = Depends(admin_only)) -> dict:
    stored = {s.key: s.value for s in db.execute(select(SystemSetting)).scalars()}
    return {k: stored.get(k, v) for k, v in DEFAULT_SETTINGS.items()}


class SettingBody(BaseModel):
    value: dict = Field(default_factory=dict)


@router.put("/settings/{key}")
def put_setting(key: str, body: SettingBody, db: DbSession = Depends(get_db), actor: User = Depends(admin_only)) -> dict:
    if key not in DEFAULT_SETTINGS:
        raise HTTPException(404, "Unknown setting")
    if key == "retention":
        for field in DEFAULT_SETTINGS["retention"]:
            v = body.value.get(field)
            if not isinstance(v, int) or isinstance(v, bool) or v < 1:
                raise HTTPException(422, f"{field} must be a positive number of days")
    value = body.value
    if key == "scan_exclusions":
        from tls_scanner.exclusions import parse_entries
        from tls_scanner.models import ConfigError

        try:
            value = {"entries": list(parse_entries(body.value.get("entries", [])))}
        except ConfigError as error:
            raise HTTPException(422, str(error)) from None
    if key == "dns_discovery":
        from tls_scan_app.services.dns_discovery.policy import DiscoveryError, validate_settings

        try:
            value = validate_settings(body.value)
        except DiscoveryError as error:
            raise HTTPException(422, str(error)) from None
    row = db.get(SystemSetting, key) or SystemSetting(key=key, value={})
    row.value = value
    db.add(row)
    audit.record(db, "settings.update", actor=actor, resource_type="settings", resource_id=key)
    db.commit()
    return {key: row.value}


@router.get("/diagnostics")
def diagnostics(request: Request, db: DbSession = Depends(get_db), _: User = Depends(admin_only)) -> dict:
    settings = request.app.state.settings
    usage = shutil.disk_usage(settings.storage_root) if __import__("os").path.isdir(settings.storage_root) else None
    return {
        "database": database_is_ready(request.app.state.engine),
        "nmap": shutil.which("nmap") is not None,
        "openssl": shutil.which("openssl") is not None,
        "storage_free_gb": round(usage.free / 1e9, 1) if usage else None,
        "active_runs": db.scalar(select(func.count()).select_from(ScanRun).where(ScanRun.status.in_(ACTIVE_STATUSES))),
        "limits": {"max_concurrent_scans": settings.max_concurrent_scans, "max_scan_duration_seconds": settings.max_scan_duration_seconds,
                   "max_addresses_per_scan": settings.max_targets_per_scan},
        "sso_configured": auth_config.effective(db, settings).oidc,
        "environment": settings.environment,
    }


@router.get("/failed-runs")
def failed_runs(db: DbSession = Depends(get_db), _: User = Depends(require_role(Role.OPERATOR))) -> list[dict]:
    """Execution errors, for OPERATOR+ troubleshooting."""
    rows = db.execute(select(ScanRun).where(ScanRun.status.in_(("failed", "expired", "partial"))).order_by(ScanRun.queued_at.desc()).limit(100)).scalars()
    return [{"id": str(r.id), "name": r.name, "status": r.status, "error": r.error, "phase": r.phase, "queued_at": r.queued_at} for r in rows]


class SmtpTestBody(BaseModel):
    to: str | None = None


@router.post("/notifications/test")
def test_notifications(body: SmtpTestBody, request: Request, db: DbSession = Depends(get_db), actor: User = Depends(admin_only)) -> list[dict]:
    from tls_scan_app.services import mail

    if mail.build_sender(db, request.app.state.settings) is None:
        raise HTTPException(409, "No complete notification connector configured")
    steps = mail.diagnose(db, request.app.state.settings, body.to)
    audit.record(db, "notifications.test", actor=actor, resource_type="settings", outcome="success" if all(s["status"] == "ok" for s in steps) else "failure")
    db.commit()
    return steps


@router.get("/notifications")
def notification_log(db: DbSession = Depends(get_db), _: User = Depends(admin_only)) -> list[dict]:
    from tls_scan_app.models import Notification

    rows = db.execute(select(Notification).order_by(Notification.created_at.desc()).limit(100)).scalars()
    return [{"id": str(n.id), "event": n.event, "subject": n.subject, "status": n.status, "error": n.error, "created_at": n.created_at,
             "sent_at": n.sent_at, "run_id": str(n.run_id) if n.run_id else None} for n in rows]


# ---- directory connectors (read-only lookup to pre-provision users) ----
class DirectoryBody(BaseModel):
    kind: str
    ldap: dict = Field(default_factory=dict)
    entra: dict = Field(default_factory=dict)
    google: dict = Field(default_factory=dict)


@router.get("/directory")
def get_directory(db: DbSession = Depends(get_db), _: User = Depends(admin_only)) -> dict:
    from tls_scan_app.connectors.registry import directory_config

    return {"kind": "none", "ldap": {}, "entra": {}, "google": {}} | directory_config(db)


@router.put("/directory")
def put_directory(body: DirectoryBody, request: Request, db: DbSession = Depends(get_db), actor: User = Depends(admin_only)) -> dict:
    from tls_scan_app.connectors.registry import KINDS

    if body.kind not in KINDS:
        raise HTTPException(422, f"kind must be one of {KINDS}")
    if body.kind == "ldap":
        from tls_scan_app.connectors.ldap_auth import LdapAuthError, require_secure

        if "starttls" in body.ldap and not isinstance(body.ldap["starttls"], bool):
            raise HTTPException(422, "LDAP StartTLS must be a boolean")
        if "tls_verify" in body.ldap and not isinstance(body.ldap["tls_verify"], bool):
            raise HTTPException(422, "LDAP certificate validation must be a boolean")
        if body.ldap.get("server_url"):
            try:
                require_secure(body.ldap)
            except LdapAuthError as error:
                raise HTTPException(422, error.message) from None
    if request.app.state.settings.environment == "production" and body.kind == "ldap" and body.ldap.get("tls_verify") is False:
        raise HTTPException(422, "LDAP server certificate validation cannot be disabled in production")
    row = db.get(SystemSetting, "directory") or SystemSetting(key="directory", value={})
    row.value = body.model_dump()
    db.add(row)
    audit.record(db, "directory.update", actor=actor, resource_type="settings", resource_id="directory", detail={"kind": body.kind})
    db.commit()
    return row.value


@router.post("/directory/test")
def test_directory(request: Request, db: DbSession = Depends(get_db), actor: User = Depends(admin_only)) -> list[dict]:
    from tls_scan_app.connectors.registry import build_connector

    connector = build_connector(db, request.app.state.settings)
    if connector is None:
        raise HTTPException(409, "No complete directory connector configured")
    steps = [s.as_dict() for s in connector.diagnose()]
    audit.record(db, "directory.test", actor=actor, resource_type="settings", outcome="success" if all(s["status"] == "ok" for s in steps) else "failure")
    db.commit()
    return steps


@router.get("/directory/search")
def search_directory(q: str, request: Request, db: DbSession = Depends(get_db), _: User = Depends(admin_only)) -> list[dict]:
    from tls_scan_app.connectors.base import ConnectorError
    from tls_scan_app.connectors.registry import build_connector

    connector = build_connector(db, request.app.state.settings)
    if connector is None:
        raise HTTPException(409, "No directory connector configured")
    if len(q.strip()) < 2:
        raise HTTPException(422, "Type at least 2 characters")
    try:
        people = connector.search(q)
    except ConnectorError as error:
        raise HTTPException(502, str(error)) from error
    existing = {u.email.lower() for u in db.execute(select(User)).scalars()}
    return [{"external_id": p.external_id, "email": p.email, "display_name": p.display_name, "provisioned": p.email.lower() in existing} for p in people]


class ProvisionBody(BaseModel):
    email: EmailStr
    display_name: str = ""
    role: Role = Role.USER


@router.post("/directory/provision", status_code=201)
def provision(body: ProvisionBody, db: DbSession = Depends(get_db), actor: User = Depends(admin_only)) -> dict:
    """Create the account in advance with the chosen role; the person's first SSO sign-in adopts it by e-mail."""
    email = body.email.lower()
    if db.execute(select(User).where(func.lower(User.email) == email)).first():
        raise HTTPException(409, "A user with this e-mail already exists")
    user = User(issuer="directory:pending", subject=email, email=email, display_name=body.display_name or email, role=body.role)
    db.add(user)
    db.flush()
    audit.record(db, "user.provision", actor=actor, resource_type="user", resource_id=user.id, detail={"email": email, "role": str(body.role)})
    db.commit()
    return user_payload(user)
