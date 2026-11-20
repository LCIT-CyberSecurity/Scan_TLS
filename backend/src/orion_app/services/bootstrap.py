"""First-start initialisation: single organisation row, local admin with the default password (changed at first sign-in)."""
from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from orion_app.auth.passwords import hash_password
from orion_app.config import Settings
from orion_app.models import Organization, Role, User
from orion_app.models.policy import PUBLISHED, Policy, PolicyVersion, ScanProfile, ScanProfileVersion
from orion_app.services import audit

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
# Built-in references for multi-technology scans (LST-38): an SSH policy and a generic profile combining TLS, IPsec and SSH.
SSH_POLICY_NAME = "SSH Baseline"
SSH_POLICY_FILE = ANSSI_POLICY_FILE.parent / "ssh_baseline_policy.yaml"
GENERIC_PROFILE_NAME = "Standard (TLS, IPsec, SSH)"
GENERIC_PROFILE_DESCRIPTION = ("Multi-technology profile: the Standard TLS settings, IKEv2 on UDP 500/4500 and a quick SSH audit on TCP 22. "
                               "Tick the technologies in each scan definition.")
GENERIC_IPSEC = {"versions": ["IKEv2"], "ports": [500, 4500], "nat_t": True, "timeout_ms": 1000, "retries": 0, "aggressive_mode": False}
GENERIC_SSH = {"ports": [22], "timeout_seconds": 2, "preset": "quick", "max_targets": 256, "retries": 0}


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


def ensure_builtin_ssh_policy(db: DbSession, path: Path = SSH_POLICY_FILE) -> None:
    """Create the "SSH Baseline" policy (technology ssh, published v1) once, from config/. Never overwritten, never recreated
    if renamed, archived or edited, exactly like the ANSSI policy."""
    if not path.is_file() or db.execute(select(Policy).where(Policy.name == SSH_POLICY_NAME)).scalar_one_or_none():
        return
    from orion_app.services.ssh_audit import validate_ssh_policy
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        content = dict(data["ssh"])
        validate_ssh_policy(content)
    except (OSError, yaml.YAMLError, KeyError, TypeError, ValueError):
        logger.warning("SSH baseline policy file %s is unreadable; not seeded", path)
        return
    policy = Policy(name=SSH_POLICY_NAME, description=" ".join(str(data.get("description", "")).split()), technology="ssh")
    db.add(policy)
    db.flush()
    db.add(PolicyVersion(policy_id=policy.id, version=1, status=PUBLISHED, content=content, published_at=datetime.now(UTC)))
    audit.record(db, "policy.builtin_seeded", actor_label="system", resource_type="policy", resource_id=str(policy.id), detail={"name": SSH_POLICY_NAME})


def ensure_builtin_generic_profile(db: DbSession, path: Path = ANSSI_PROFILE_FILE) -> None:
    """Create the "Standard (TLS, IPsec, SSH)" generic profile (published v1) once: its TLS section is the Standard profile's
    content, from the same config/config.yaml defaults. Never overwritten, never recreated if renamed, archived or edited."""
    if not path.is_file() or db.execute(select(ScanProfile).where(ScanProfile.name == GENERIC_PROFILE_NAME)).scalar_one_or_none():
        return
    from orion_app.services.planner import PlanError, validate_generic_profile_content
    try:
        defaults = yaml.safe_load(path.read_text(encoding="utf-8"))["defaults"]
        content = {"tls": {"scan": defaults["scan"], "checks": defaults["checks"]}, "ipsec": {"ike": dict(GENERIC_IPSEC)}, "ssh": dict(GENERIC_SSH)}
        validate_generic_profile_content(content)
    except (OSError, yaml.YAMLError, KeyError, TypeError, ValueError, PlanError):
        logger.warning("Scan defaults in %s are unreadable; multi-technology profile not seeded", path)
        return
    profile = ScanProfile(name=GENERIC_PROFILE_NAME, description=GENERIC_PROFILE_DESCRIPTION, technology="generic")
    db.add(profile)
    db.flush()
    db.add(ScanProfileVersion(profile_id=profile.id, version=1, status=PUBLISHED, content=content, published_at=datetime.now(UTC)))
    audit.record(db, "profile.builtin_seeded", actor_label="system", resource_type="profile", resource_id=str(profile.id), detail={"name": GENERIC_PROFILE_NAME})


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
    ensure_builtin_ssh_policy(db)
    ensure_builtin_profiles(db)
    ensure_builtin_generic_profile(db)
    db.commit()

