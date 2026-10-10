"""First-start initialisation: single organisation row, local admin with the default password (changed at first sign-in)."""
from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from tls_scan_app.auth.passwords import hash_password
from tls_scan_app.config import Settings
from tls_scan_app.models import Organization, Role, User
from tls_scan_app.services import audit

logger = logging.getLogger(__name__)
LOCAL_ISSUER = "builtin:local"
DEFAULT_ADMIN_PASSWORD = "SecretPassword"  # noqa: S105  deployment default, must be changed at first sign-in (as in LCIT-Sign)


def ensure_bootstrap(db: DbSession, settings: Settings) -> None:
    if db.get(Organization, 1) is None:
        db.add(Organization(id=1))
    admin = db.execute(
        select(User).where(User.issuer == LOCAL_ISSUER, User.subject == settings.local_admin_username)
    ).scalar_one_or_none()
    if admin is None:
        password = settings.local_admin_password or DEFAULT_ADMIN_PASSWORD
        admin = User(
            issuer=LOCAL_ISSUER,
            subject=settings.local_admin_username,
            email=f"{settings.local_admin_username}@local",
            display_name="Local administrator",
            password_hash=hash_password(password),
            must_change_password=True,
            role=Role.ADMIN,
        )
        db.add(admin)
        audit.record(db, "user.bootstrap_admin", actor_label="system", resource_type="user", detail={"username": admin.subject})
    db.commit()

