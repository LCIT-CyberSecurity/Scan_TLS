"""Turn a scan definition into an exact, immutable snapshot, and a snapshot into an engine `ScanJob`.

The snapshot (stored in scan_runs.config_snapshot) is the single contract between the API, the
scheduler and the worker: the worker needs nothing else to run a scan.
"""
from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from tls_scan_app.models import (
    DefinitionGroup, DefinitionPolicy, DefinitionTarget, PolicyVersion, ReportTemplate, ScanDefinition,
    ScanProfileVersion, Target, TargetGroupMember,
)
from tls_scan_app.models.policy import PUBLISHED
from tls_scan_app.services.targets import address_count
from tls_scanner.config import build_job_from_sections
from tls_scanner.constants import ALLOWED_EXPORT_FORMATS
from tls_scanner.models import ConfigError, EncryptionPolicy

DEFAULT_FORMATS = ["html", "md", "csv", "cbom"]
POLICY_KEYS = ("allowed_versions", "allowed_cipher_algorithms", "allowed_signature_hashes", "minimum_rsa_bits")


class PlanError(ValueError):
    pass


def validate_profile_content(content: dict[str, Any]) -> None:
    """Validate with the engine's own parser, so the WebUI accepts exactly what YAML accepts."""
    allowed = {"scan", "checks"}
    if set(content) - allowed:
        raise PlanError(f"unsupported profile sections: {sorted(set(content) - allowed)}")
    checks = content.get("checks", {})
    stores = ((checks.get("certificate") or {}).get("trust") or {}).get("custom_stores") or []
    if stores:
        raise PlanError("custom trust stores are not supported in the WebUI in V1")
    try:
        build_job_from_sections(content.get("scan", {}), {}, {}, ["192.0.2.1"], None, checks)
    except ConfigError as error:
        raise PlanError(str(error)) from error


def validate_policy_content(content: dict[str, Any]) -> None:
    for key in ("allowed_versions", "allowed_cipher_algorithms", "allowed_signature_hashes"):
        values = content.get(key)
        if not isinstance(values, list) or not values or not all(isinstance(v, str) for v in values):
            raise PlanError(f"{key} must be a non-empty list of strings")
    bits = content.get("minimum_rsa_bits")
    if not isinstance(bits, int) or isinstance(bits, bool) or bits < 1:
        raise PlanError("minimum_rsa_bits must be a positive integer")
    if set(content) - set(POLICY_KEYS):
        raise PlanError(f"unsupported policy fields: {sorted(set(content) - set(POLICY_KEYS))}")


def latest_published(db: DbSession, model, fk_column, parent_id):
    return db.execute(
        select(model).where(fk_column == parent_id, model.status == PUBLISHED).order_by(model.version.desc()).limit(1)
    ).scalar_one_or_none()


def resolve_targets(db: DbSession, definition: ScanDefinition) -> list[Target]:
    direct = db.execute(
        select(Target).join(DefinitionTarget, DefinitionTarget.target_id == Target.id).where(
            DefinitionTarget.definition_id == definition.id
        )
    ).scalars().all()
    grouped = db.execute(
        select(Target)
        .join(TargetGroupMember, TargetGroupMember.target_id == Target.id)
        .join(DefinitionGroup, DefinitionGroup.group_id == TargetGroupMember.group_id)
        .where(DefinitionGroup.definition_id == definition.id)
    ).scalars().all()
    unique = {t.id: t for t in [*direct, *grouped]}  # same target via several paths: counted once
    return sorted(unique.values(), key=lambda t: (t.value, t.ports))


def build_snapshot(db: DbSession, definition: ScanDefinition, max_addresses: int) -> dict[str, Any]:
    profile_version = latest_published(db, ScanProfileVersion, ScanProfileVersion.profile_id, definition.profile_id)
    if profile_version is None:
        raise PlanError("the scan profile has no published version")
    scan_cfg = copy.deepcopy(profile_version.content.get("scan", {}))
    default_ports = scan_cfg.get("ports", "fast")

    targets = resolve_targets(db, definition)
    if not targets:
        raise PlanError("the scan definition has no target")
    total = sum(address_count(t.value, t.kind) for t in targets)
    if total > max_addresses:
        raise PlanError(f"too many addresses ({total} > {max_addresses})")
    by_ports: dict[str, list[str]] = {}
    for target in targets:
        by_ports.setdefault(target.ports or str(default_ports), []).append(target.value)
    passes = [{"ports": ports, "targets": sorted(set(values))} for ports, values in sorted(by_ports.items())]

    policy_ids = db.execute(
        select(DefinitionPolicy.policy_id).where(DefinitionPolicy.definition_id == definition.id)
    ).scalars().all()
    policies = []
    for policy_id in policy_ids:
        version = latest_published(db, PolicyVersion, PolicyVersion.policy_id, policy_id)
        if version is None:
            raise PlanError("a selected policy has no published version")
        from tls_scan_app.models import Policy

        name = db.get(Policy, policy_id).name
        policies.append({"policy_id": str(policy_id), "version_id": str(version.id), "name": name,
                         "version": version.version, "content": version.content})
    if not policies:
        raise PlanError("at least one policy is required")
    policies.sort(key=lambda p: p["name"])

    template = db.get(ReportTemplate, definition.report_template_id) if definition.report_template_id else None
    formats = [f for f in (template.export_formats if template else DEFAULT_FORMATS) if f in ALLOWED_EXPORT_FORMATS]
    return {
        "definition": {"id": str(definition.id), "name": definition.name},
        "profile": {"id": str(definition.profile_id), "version_id": str(profile_version.id), "version": profile_version.version},
        "scan": scan_cfg,
        "checks": copy.deepcopy(profile_version.content.get("checks", {})),
        "passes": passes,
        "policy_mode": definition.policy_mode,
        "policies": policies,
        "export_formats": formats,
        "branding": (template.branding if template else None) or {},
    }


def fingerprint(snapshot: dict[str, Any]) -> str:
    """Hash of everything that influences observations (not the output formats nor worker count)."""
    scan = {k: v for k, v in snapshot["scan"].items() if k != "workers"}
    material = {
        "passes": snapshot["passes"],
        "scan": scan,
        "checks": snapshot["checks"],
        "policies": [(p["name"], p["version_id"]) for p in snapshot["policies"]],
        "mode": snapshot["policy_mode"],
    }
    return hashlib.sha256(json.dumps(material, sort_keys=True, default=str).encode()).hexdigest()


def job_from_snapshot(snapshot: dict[str, Any], run_id: str, export_dir: str, log_file: str | None, max_workers: int):
    """Build the engine ScanJob. Returns (job, passes) where passes = [(targets, ports)]."""
    passes = [(",".join(p["targets"]), str(p["ports"])) for p in snapshot["passes"]]
    all_targets = [t for p in snapshot["passes"] for t in p["targets"]]
    scan_cfg = dict(snapshot["scan"])
    scan_cfg["workers"] = min(int(scan_cfg.get("workers", 4)), max_workers)
    try:
        job = build_job_from_sections(
            scan_cfg,
            {"directory": export_dir, "formats": snapshot["export_formats"], "filename_template": "{timestamp}_{report_name}"},
            {"level": "info", "file": log_file},
            all_targets,
            {"name": _safe_name(snapshot["definition"]["name"]), "frequency": "webui"},
            snapshot["checks"],
        )
    except ConfigError as error:
        raise PlanError(str(error)) from error
    job.policies = tuple(
        EncryptionPolicy(
            name=p["name"], version=str(p["version"]), description="", path="",
            allowed_versions=tuple(p["content"]["allowed_versions"]),
            allowed_cipher_algorithms=tuple(p["content"]["allowed_cipher_algorithms"]),
            allowed_signature_hashes=tuple(p["content"]["allowed_signature_hashes"]),
            minimum_rsa_bits=int(p["content"]["minimum_rsa_bits"]),
        )
        for p in snapshot["policies"]
    )
    job.policy_mode = snapshot["policy_mode"]
    job.scan_run_id = run_id
    return job, passes


def _safe_name(name: str) -> str:
    cleaned = "".join(c if c.isalnum() or c in "-_" else "_" for c in name)[:60].strip("_-")
    return cleaned or "scan"
