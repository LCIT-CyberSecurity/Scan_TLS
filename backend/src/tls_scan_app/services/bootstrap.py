"""First-start initialisation: single organisation row, local admin with the default password (changed at first sign-in)."""
from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from tls_scan_app.auth.passwords import hash_password
from tls_scan_app.config import Settings
from tls_scan_app.models import Organization, Role, User
from tls_scan_app.models.policy import PUBLISHED, Policy, PolicyVersion, ScanProfile, ScanProfileVersion
from tls_scan_app.services import audit

logger = logging.getLogger(__name__)
LOCAL_ISSUER = "builtin:local"
DEFAULT_ADMIN_PASSWORD = "SecretPassword"  # noqa: S105  deployment default, must be changed at first sign-in (as in LCIT-Sign)


# The ANSSI policy shipped in config/ (same file as the Standalone engine) is available natively, already published.
ANSSI_POLICY_NAME = "ANSSI"
ANSSI_POLICY_FILE = Path(__file__).resolve().parents[4] / "config" / "encryption_policy" / "anssi_encryption_policy.yaml"
STANDARD_PROFILE_NAME = "Standard"
PROFILE_DESCRIPTION = "Standard scan profile: engine defaults (standard ciphers, certificate trust and revocation checks)."
ANSSI_PROFILE_FILE = ANSSI_POLICY_FILE.parents[1] / "config.yaml"  # scan profile: the engine's `defaults` section
POLICY_FIELDS = ("allowed_versions", "allowed_cipher_algorithms", "allowed_signature_hashes", "minimum_rsa_bits")


def ensure_builtin_policies(db: DbSession, path: Path = ANSSI_POLICY_FILE) -> None:
    """Create the ANSSI policy (published v1) once. Never overwritten, never recreated if renamed, archived or edited."""
    if not path.is_file() or db.execute(select(Policy).where(Policy.name == ANSSI_POLICY_NAME)).scalar_one_or_none():
        return
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        content = {key: data["tls"][key] for key in POLICY_FIELDS}
    except (OSError, yaml.YAMLError, KeyError, TypeError):
        logger.warning("ANSSI policy file %s is unreadable; not seeded", path)
        return
    policy = Policy(name=ANSSI_POLICY_NAME, description=str(data.get("description", "")))
    db.add(policy)
    db.flush()
    db.add(PolicyVersion(policy_id=policy.id, version=1, status=PUBLISHED, content=content, published_at=datetime.now(UTC)))
    audit.record(db, "policy.builtin_seeded", actor_label="system", resource_type="policy", resource_id=str(policy.id), detail={"name": ANSSI_POLICY_NAME})


def ensure_builtin_profiles(db: DbSession, path: Path = ANSSI_PROFILE_FILE) -> None:
    """Create the built-in "Standard" scan profile (published v1) from config/config.yaml `defaults`, once.

    An earlier release seeded it under the name "ANSSI" (that name now belongs to the policy only): rename it
    when it is still unnamed-by-anyone-else, i.e. no profile called "Standard" exists yet.
    """
    if db.execute(select(ScanProfile).where(ScanProfile.name == STANDARD_PROFILE_NAME)).scalar_one_or_none():
        return
    legacy = db.execute(select(ScanProfile).where(ScanProfile.name == ANSSI_POLICY_NAME)).scalar_one_or_none()
    if legacy is not None:
        legacy.name = STANDARD_PROFILE_NAME
        if legacy.description.startswith("ANSSI scan profile"):
            legacy.description = PROFILE_DESCRIPTION
        return
    if not path.is_file():
        return
    try:
        defaults = yaml.safe_load(path.read_text(encoding="utf-8"))["defaults"]
        content = {"scan": defaults["scan"], "checks": defaults["checks"]}
    except (OSError, yaml.YAMLError, KeyError, TypeError):
        logger.warning("Scan defaults in %s are unreadable; Standard profile not seeded", path)
        return
    profile = ScanProfile(name=STANDARD_PROFILE_NAME, description=PROFILE_DESCRIPTION)
    db.add(profile)
    db.flush()
    db.add(ScanProfileVersion(profile_id=profile.id, version=1, status=PUBLISHED, content=content, published_at=datetime.now(UTC)))
    audit.record(db, "profile.builtin_seeded", actor_label="system", resource_type="profile", resource_id=str(profile.id), detail={"name": STANDARD_PROFILE_NAME})


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
    ensure_builtin_policies(db)
    ensure_builtin_profiles(db)
    db.commit()

