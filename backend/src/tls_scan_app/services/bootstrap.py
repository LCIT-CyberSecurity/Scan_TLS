"""First-start initialisation: single organisation row, local admin with a generated password."""
from __future__ import annotations

import logging
import os
import secrets
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from tls_scan_app.auth.passwords import hash_password
from tls_scan_app.config import Settings
from tls_scan_app.models import Organization, Role, User
from tls_scan_app.services import audit

logger = logging.getLogger(__name__)
LOCAL_ISSUER = "builtin:local"


def ensure_bootstrap(db: DbSession, settings: Settings) -> None:
    if db.get(Organization, 1) is None:
        db.add(Organization(id=1))
    admin = db.execute(
        select(User).where(User.issuer == LOCAL_ISSUER, User.subject == settings.local_admin_username)
    ).scalar_one_or_none()
    if admin is None:
        password = settings.local_admin_password or secrets.token_urlsafe(18)
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
        if not settings.local_admin_password:
            _write_initial_password(Path(settings.initial_password_path), password)
            logger.warning("Initial administrator created; its one-time password is in %s", settings.initial_password_path)
    db.commit()


def _write_initial_password(path: Path, password: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(password + "\n")
