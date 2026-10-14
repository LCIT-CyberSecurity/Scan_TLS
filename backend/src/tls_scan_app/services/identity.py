"""Who an external sign-in (OIDC or LDAP) is in TLS Scan: find or create the account, never taking one over.

Rules, shared by every provider:
- the stable key is (issuer, subject), never the e-mail;
- an account pre-provisioned by an administrator (`directory:pending`) is adopted by e-mail, and only that kind of account:
  a local, SSO or LDAP account is never claimed through an e-mail match;
- a first-time user is created (with the default role, never ADMIN) only when the administrator allows it;
- a disabled account is refused whatever the provider.
"""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from tls_scan_app.models import Role, User
from tls_scan_app.services import audit

PENDING = "directory:pending"


class SignInRefused(Exception):
    """The identity is valid but may not enter. `reason` is for the audit log, never shown to the browser."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(reason)
        self.reason, self.detail = reason, detail


@dataclass(frozen=True)
class External:
    issuer: str
    subject: str
    email: str
    name: str = ""


def source_of(issuer: str) -> str:
    """Where an account signs in from, for the Users list."""
    low = (issuer or "").lower()
    if low in ("builtin:local", "local:user") or low.startswith("local:"):
        return "local"
    if low == PENDING:
        return "pending"
    if low.startswith("ldap:"):
        return "ldap"
    if "accounts.google.com" in low:
        return "google"
    if "login.microsoftonline.com" in low or "sts.windows.net" in low or "microsoftonline" in low:
        return "entra"
    return "sso"


def resolve(db: DbSession, who: External, *, auto_provision: bool, default_role: str) -> User:
    user = db.execute(select(User).where(User.issuer == who.issuer, User.subject == who.subject)).scalar_one_or_none()
    if user is None and who.email:
        pending = db.execute(select(User).where(User.issuer == PENDING, func.lower(User.email) == who.email.lower())).scalar_one_or_none()
        if pending is not None:
            pending.issuer, pending.subject = who.issuer, who.subject
            user = pending
    if user is None:
        if not auto_provision:
            raise SignInRefused("not_provisioned", who.email)
        if who.email and db.execute(select(User).where(func.lower(User.email) == who.email.lower())).first():
            # Same address under another identity (a local account, another provider): never merge, never duplicate silently.
            raise SignInRefused("email_conflict", who.email)
        role = Role(default_role) if default_role in ("AUDITOR", "USER", "OPERATOR") else Role.USER
        user = User(issuer=who.issuer, subject=who.subject, email=who.email.lower(), display_name=who.name or who.email, role=role)
        db.add(user)
        db.flush()
        audit.record(db, "user.sso_provisioned", actor=user, resource_type="user", resource_id=user.id, detail={"role": str(user.role), "source": source_of(who.issuer)})
    else:
        if who.email:
            user.email = who.email.lower()
        user.display_name = who.name or user.display_name
    if not user.active:
        raise SignInRefused("account_disabled", who.email)
    return user
