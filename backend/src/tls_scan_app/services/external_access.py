"""External access (REST API v1 and MCP): global switches, per-user authorisation and access keys.

The rules are re-evaluated at every request from the database: nothing about a user or a key is cached in the key.
A key never authenticates anything but its own service; a session never authenticates the external services.
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session as DbSession

from tls_scan_app.models import AccessToken, SystemSetting, User
from tls_scan_app.services import audit

SETTING_KEY = "external_access"
SERVICES = ("api", "mcp")
PREFIXES = {"api": "tls_scan_pat_", "mcp": "tls_scan_mcp_"}
VALID_DAYS = 90
LAST_USED_GRANULARITY = timedelta(seconds=60)


class AccessError(Exception):
    """A refusal that must not tell the caller why (they get a generic 401)."""


class AccessUnavailable(ValueError):
    """Key generation refused with an explicit, user-facing reason."""


def _flag(user: User, service: str) -> bool:
    return bool(user.api_access_enabled if service == "api" else user.mcp_access_enabled)


def global_state(db: DbSession) -> dict[str, bool]:
    row = db.get(SystemSetting, SETTING_KEY)
    value = row.value if row else {}
    return {"api_enabled": bool(value.get("api_enabled", False)), "mcp_enabled": bool(value.get("mcp_enabled", False))}


def service_enabled(db: DbSession, service: str) -> bool:
    return global_state(db)[f"{service}_enabled"]


def set_service_enabled(db: DbSession, service: str, enabled: bool, actor: User) -> bool:
    """Persists the switch; returns True when the value changed. Existing keys are suspended, not revoked."""
    state = global_state(db)
    changed = state[f"{service}_enabled"] != enabled
    state[f"{service}_enabled"] = enabled
    row = db.get(SystemSetting, SETTING_KEY)
    if row is None:
        db.add(SystemSetting(key=SETTING_KEY, value=state))
    else:
        row.value = dict(state)
    audit.record(db, f"external_access.{service}_{'enabled' if enabled else 'disabled'}", actor=actor, resource_type="setting",
                 resource_id=SETTING_KEY, detail={"changed": changed})
    return changed


def _digest(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def active_token(db: DbSession, user_id, service: str) -> AccessToken | None:
    row = db.execute(select(AccessToken).where(AccessToken.user_id == user_id, AccessToken.service == service,
                                               AccessToken.revoked_at.is_(None))).scalar_one_or_none()
    if row is not None and _aware(row.expires_at) <= _now():
        return None
    return row


def token_summary(db: DbSession, user_id, service: str) -> dict:
    row = active_token(db, user_id, service)
    if row is None:
        return {"active": False, "prefix": None, "created_at": None, "expires_at": None, "last_used_at": None}
    return {"active": True, "prefix": row.prefix, "created_at": row.created_at, "expires_at": row.expires_at, "last_used_at": row.last_used_at}


def create_token(db: DbSession, user: User, service: str) -> dict:
    """Generates the user's own key (the previous one is revoked). The secret is returned once and never stored."""
    if service not in SERVICES:
        raise AccessUnavailable("Unknown service")
    if not service_enabled(db, service):
        raise AccessUnavailable("This service is currently disabled by the administrator")
    if not user.active or not _flag(user, service):
        raise AccessUnavailable("Your account is not authorised to use this service")
    now = _now()
    db.execute(update(AccessToken).where(AccessToken.user_id == user.id, AccessToken.service == service,
                                         AccessToken.revoked_at.is_(None)).values(revoked_at=now))
    secret = PREFIXES[service] + secrets.token_urlsafe(36)
    row = AccessToken(user_id=user.id, service=service, prefix=secret[:len(PREFIXES[service]) + 6], token_hash=_digest(secret),
                      expires_at=now + timedelta(days=VALID_DAYS))
    db.add(row)
    db.flush()
    return {"token": secret, "prefix": row.prefix, "created_at": row.created_at or now, "expires_at": row.expires_at}


def revoke_tokens(db: DbSession, user_id, service: str | None = None) -> int:
    stmt = update(AccessToken).where(AccessToken.user_id == user_id, AccessToken.revoked_at.is_(None)).values(revoked_at=_now())
    if service:
        stmt = stmt.where(AccessToken.service == service)
    return db.execute(stmt).rowcount or 0


@dataclass(frozen=True)
class Principal:
    user: User
    token_id: str
    prefix: str
    service: str


def authenticate(db: DbSession, secret: str, service: str) -> Principal:
    """Raises AccessError for every refusal. Checks, in order: the key's family, global switch, key, expiry, revocation,
    user active, individual authorisation, password change pending. The role is read from the user row each time."""
    if not secret.startswith(PREFIXES[service]):
        raise AccessError("prefix")
    if not service_enabled(db, service):
        raise AccessError("service disabled")
    row = db.execute(select(AccessToken).where(AccessToken.token_hash == _digest(secret), AccessToken.service == service)).scalar_one_or_none()
    if row is None or not secrets.compare_digest(row.token_hash, _digest(secret)):
        raise AccessError("unknown key")
    if row.revoked_at is not None:
        raise AccessError("revoked")
    if _aware(row.expires_at) <= _now():
        raise AccessError("expired")
    user = db.get(User, row.user_id)
    if user is None or not user.active:
        raise AccessError("user inactive")
    if not _flag(user, service):
        raise AccessError("not authorised")
    if user.must_change_password:
        raise AccessError("password change pending")
    if row.last_used_at is None or _now() - _aware(row.last_used_at) > LAST_USED_GRANULARITY:
        row.last_used_at = _now()
        db.commit()
    return Principal(user=user, token_id=str(row.id), prefix=row.prefix, service=service)


def set_user_access(db: DbSession, user: User, actor: User, api: bool | None, mcp: bool | None) -> None:
    """Administrator grants or withdraws the services for a user. Withdrawing revokes the keys immediately."""
    for service, value in (("api", api), ("mcp", mcp)):
        if value is None or _flag(user, service) == value:
            continue
        setattr(user, f"{service}_access_enabled", value)
        revoked = 0 if value else revoke_tokens(db, user.id, service)
        audit.record(db, f"external_access.user_{service}_{'granted' if value else 'withdrawn'}", actor=actor, resource_type="user",
                     resource_id=user.id, detail={"revoked_keys": revoked})
