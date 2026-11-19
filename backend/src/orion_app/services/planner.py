"""Turn a scan definition into an exact, immutable snapshot, and a snapshot into an engine `ScanJob`.

The snapshot (stored in scan_runs.config_snapshot) is the single contract between the API, the
scheduler and the worker: the worker needs nothing else to run a scan.
"""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import unicodedata
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession
from tls_scanner.config import build_job_from_sections
from tls_scanner.constants import ALLOWED_EXPORT_FORMATS
from tls_scanner.exclusions import Exclusions
from tls_scanner.exclusions import parse_entries as parse_exclusions
from tls_scanner.models import ConfigError, EncryptionPolicy

from orion_app.models import (
    DefinitionGroup,
    DefinitionPolicy,
    DefinitionTarget,
    EndpointExposure,
    PolicyVersion,
    ReportTemplate,
    ScanDefinition,
    ScanProfile,
    ScanProfileVersion,
    SystemSetting,
    Target,
    TargetGroupMember,
)
from orion_app.models.policy import PUBLISHED
from orion_app.services.targets import address_count
from orion_app.services.trust_stores import TrustStoreError, resolve_for_snapshot

DEFAULT_FORMATS = ["html", "md", "csv", "cbom"]
POLICY_KEYS = ("allowed_versions", "allowed_cipher_algorithms", "allowed_signature_hashes", "minimum_rsa_bits")


class PlanError(ValueError):
    pass


def validate_profile_content(content: dict[str, Any]) -> None:
    """Validate with the engine's own parser, so the WebUI accepts exactly what YAML accepts."""
    allowed = {"scan", "checks", "service_identification"}
    if set(content) - allowed:
        raise PlanError(f"unsupported profile sections: {sorted(set(content) - allowed)}")
    checks = content.get("checks", {})
    trust = (checks.get("certificate") or {}).get("trust") or {}
    if trust.get("custom_stores"):
        raise PlanError("file-based trust stores are not available in the WebUI: use Administration > Trust authorities")
    if trust.get("inline_stores"):
        raise PlanError("inline certificates are not accepted in a profile: import them in Administration > Trust authorities")
    try:
        # `private_stores` (administered store ids) is resolved at launch time; the engine only sees the stores inlined by the planner
        engine_checks = copy.deepcopy(checks)
        ((engine_checks.get("certificate") or {}).get("trust") or {}).pop("private_stores", None)
        engine_scan = copy.deepcopy(content.get("scan", {}))
        quic = engine_scan.pop("quic", None)
        if quic is not None:
            from orion_app.services.quic_scan import validate_profile
            validate_profile(quic)
        build_job_from_sections(engine_scan, {}, {}, ["192.0.2.1"], None, engine_checks)
    except ConfigError as error:
        raise PlanError(str(error)) from error
    if "service_identification" in content:
        validate_service_identification_profile(content["service_identification"])


def validate_service_identification_profile(content: Any) -> None:
    """Validate fixed Nmap service-probe budgets; no command or NSE options are user-configurable."""
    if not isinstance(content, dict) or set(content) - {"strategy", "max_targets", "max_services", "timeout_seconds", "max_parallelism"}:
        raise PlanError("service_identification contains unsupported fields")
    strategy = content.get("strategy", "fast")
    limits = {
        "max_targets": (1, 128, 64),
        "max_services": (1, 500, 200),
        "timeout_seconds": (5, 90, 45),
        "max_parallelism": (1, 10, 5),
    }
    if strategy not in {"fast", "detailed"}:
        raise PlanError("service_identification.strategy must be fast or detailed")
    for key, (minimum, maximum, _default) in limits.items():
        value = content.get(key, _default)
        if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
            raise PlanError(f"service_identification.{key} must be between {minimum} and {maximum}")


def validate_generic_profile_content(content: dict[str, Any]) -> None:
    """Validate independent, versioned sections for the currently available engines."""
    if (not isinstance(content, dict) or not content or set(content) - {"tls", "ipsec", "ssh", "service_identification"}
            or not set(content).intersection({"tls", "ipsec", "ssh"})):
        raise PlanError("generic profiles may contain tls, ipsec, ssh and service_identification sections")
    if "tls" in content:
        validate_profile_content(content["tls"])
    if "ipsec" in content:
        from orion_app.services.ipsec import validate_ipsec_profile
        validate_ipsec_profile(content["ipsec"])
    if "ssh" in content:
        from orion_app.services.ssh_audit import validate_ssh_profile
        validate_ssh_profile({"ssh": content["ssh"]})
    if "service_identification" in content:
        validate_service_identification_profile(content["service_identification"])


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


def _service_identification_snapshot(definition: ScanDefinition, profile_content: dict[str, Any]) -> dict[str, Any] | None:
    if not definition.service_identification_enabled:
        return None
    settings = profile_content.get("service_identification") or {}
    return {
        "enabled": True,
        "strategy": settings.get("strategy", "fast"),
        "max_targets": settings.get("max_targets", 64),
        "max_services": settings.get("max_services", 200),
        "timeout_seconds": settings.get("timeout_seconds", 45),
        "max_parallelism": settings.get("max_parallelism", 5),
        "source": "nmap -sV; selected target scope only",
    }


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


def exposure_snapshot(db: DbSession, targets: list[Target]) -> list[dict[str, Any]]:
    """Capture endpoint context at queue time; no address inference or live lookups are performed."""
    ids = [target.id for target in targets]
    if not ids:
        return []
    values = {target.id: target.value for target in targets}
    return [{"target_value": values[row.target_id], "protocol": row.protocol, "port": row.port, "sni": row.sni,
             "state": row.state if row.validated else "unknown",
             "proposed_state": row.state if not row.validated and row.state != "unknown" else None,
             "zone_context": row.zone_context, "evidence_method": row.evidence_method,
             "source": row.source, "justification": row.justification, "confidence": row.confidence,
             "validated": row.validated, "observed_at": row.observed_at.isoformat() if row.observed_at else None,
             "validated_at": row.validated_at.isoformat() if row.validated_at else None}
            for row in db.execute(select(EndpointExposure).where(EndpointExposure.target_id.in_(ids))
                                  .order_by(EndpointExposure.target_id, EndpointExposure.protocol, EndpointExposure.port, EndpointExposure.sni)).scalars()]


def build_snapshot(db: DbSession, definition: ScanDefinition, max_addresses: int) -> dict[str, Any]:
    profile_version = latest_published(db, ScanProfileVersion, ScanProfileVersion.profile_id, definition.profile_id)
    if profile_version is None:
        raise PlanError("the scan profile has no published version")
    profile_content = profile_version.content
    is_generic = db.get(ScanProfile, definition.profile_id).technology == "generic"
    selected = list(definition.enabled_controls or [])
    if not selected:
        selected = [definition.control_type]
    if set(selected) - {"tls", "ipsec", "ssh"} or not selected:
        raise PlanError("this profile contains controls that are not yet available")
    if is_generic:
        if set(selected) - set(profile_content):
            raise PlanError("the selected profile does not configure every enabled technology")
        tls_profile = profile_content.get("tls", {})
        ipsec_profile = profile_content.get("ipsec", {})
        ssh_profile = profile_content.get("ssh", {})
    else:
        if definition.enabled_controls:
            raise PlanError("multiple controls require a generic scan profile")
        tls_profile = profile_content if definition.control_type == "tls" else {}
        ipsec_profile = profile_content if definition.control_type == "ipsec" else {}
        ssh_profile = {}
    scan_cfg = copy.deepcopy(tls_profile.get("scan", {}))
    quic_profile = scan_cfg.pop("quic", {})
    from orion_app.services.quic_scan import effective_config
    quic_config = effective_config(quic_profile, definition.quic_enabled) if "tls" in selected else None
    default_ports = scan_cfg.get("ports", "fast")
    service_identification = _service_identification_snapshot(definition, profile_content)

    targets = resolve_targets(db, definition)
    if not targets:
        raise PlanError("the scan definition has no target")
    # exclusions: the administrator's global list, the definition's own list and the profile's `scan.exclude`
    sources: dict[str, str] = {}
    try:
        glob = db.get(SystemSetting, "scan_exclusions")
        for scope, raw in (("global", (glob.value if glob else {}).get("entries", [])), ("definition", definition.exclusions or []), ("profile", scan_cfg.get("exclude") or [])):
            for entry in parse_exclusions(raw):
                sources.setdefault(entry, scope)
    except ConfigError as error:
        raise PlanError(f"invalid exclusion: {error}") from error
    exclusions = Exclusions(tuple(sources))
    removed: list[str] = []
    partial: list[str] = []
    if exclusions:
        by_value = {t.value: t for t in targets}
        kept, removed, partial = exclusions.filter_targets(list(by_value))
        targets = [t for t in targets if t.value in set(kept)]
        if not targets:
            raise PlanError("every target is excluded: nothing to scan")
        scan_cfg["exclude"] = list(sources)
    total = sum(address_count(t.value, t.kind) for t in targets)
    if total > max_addresses:
        raise PlanError(f"too many addresses ({total} > {max_addresses})")
    by_ports: dict[str, list[str]] = {}
    for target in targets:
        by_ports.setdefault(target.ports or str(default_ports), []).append(target.value)
    passes = [{"ports": ports, "targets": sorted(set(values))} for ports, values in sorted(by_ports.items())]
    exposures_snapshot = exposure_snapshot(db, targets)

    policy_ids = db.execute(
        select(DefinitionPolicy.policy_id).where(DefinitionPolicy.definition_id == definition.id)
    ).scalars().all()
    policies = []
    for policy_id in policy_ids:
        version = latest_published(db, PolicyVersion, PolicyVersion.policy_id, policy_id)
        if version is None:
            raise PlanError("a selected policy has no published version")
        from orion_app.models import Policy

        name = db.get(Policy, policy_id).name
        policies.append({"policy_id": str(policy_id), "version_id": str(version.id), "name": name,
                         "version": version.version, "content": version.content})
    if not policies:
        raise PlanError("at least one policy is required")
    from orion_app.models import Policy
    technologies = {db.get(Policy, p["policy_id"]).technology for p in policies}
    missing = set(selected) - technologies
    if missing:
        raise PlanError(f"a published encryption policy is required for each enabled technology: {sorted(missing)}")
    policy_bundles = {technology: [p for p in policies if db.get(Policy, p["policy_id"]).technology == technology]
                      for technology in ("tls", "ipsec", "ssh")}
    policies.sort(key=lambda p: p["name"])
    template = db.get(ReportTemplate, definition.report_template_id) if definition.report_template_id else None
    formats = [f for f in (template.export_formats if template else DEFAULT_FORMATS) if f in ALLOWED_EXPORT_FORMATS]

    if selected == ["ipsec"]:
        ike = copy.deepcopy(ipsec_profile["ike"])
        probe_targets = []
        for target in targets:
            if target.kind == "cidr":
                probe_targets.extend(str(address) for address in ipaddress.ip_network(target.value, strict=False))
            else:
                probe_targets.append(target.value)
        if exclusions:
            probe_targets, _, _ = exclusions.filter_targets(probe_targets)
        if not probe_targets:
            raise PlanError("every target address is excluded: nothing to probe")
        # Legacy IPsec-only snapshots keep the historical shape below.
        return {
            "control_type": "ipsec", "definition": {"id": str(definition.id), "name": definition.name},
            "profile": {"id": str(definition.profile_id), "version_id": str(profile_version.id), "version": profile_version.version},
            "ike": ike, "scan": scan_cfg, "service_identification": service_identification,
            "exposure_snapshot": exposures_snapshot,
            "quic": None,
            "passes": [{"targets": sorted(set(probe_targets)), "ports": str(default_ports)}], "policies": policy_bundles["ipsec"],
            "policy_mode": definition.policy_mode, "export_formats": [f for f in formats if f in {"html", "md", "csv"}], "branding": (template.branding if template else None) or {},
            "limitations": ["Unauthenticated IKE exchange only", "ESP/Child SA, authentication, PFS and tunnel operation are not evaluated"],
        }

    mail_security = copy.deepcopy(definition.mail_security or {"enabled": False, "checks": {}, "dkim_selectors": []})
    mail_security["enabled"] = bool(mail_security.get("enabled"))
    if mail_security["enabled"]:
        mail_security["checks"] = {key: bool((mail_security.get("checks") or {}).get(key))
                                    for key in ("spf", "dmarc", "dkim", "mta_sts", "tls_rpt", "dane")}
        if not any(mail_security["checks"].values()):
            raise PlanError("enable at least one mail security check")
        mail_domains = sorted({target.value.rstrip(".").lower() for target in targets if target.kind == "fqdn"})
        if exclusions:
            mail_domains, _, _ = exclusions.filter_targets(mail_domains)
        if not mail_domains:
            raise PlanError("mail security checks require at least one explicitly selected FQDN target; IP/CIDR targets are not inferred as mail domains")
        if len(mail_domains) > 25:
            raise PlanError("mail security checks are limited to 25 explicitly selected FQDNs per scan")
        mail_security["domains"] = mail_domains
        mail_security["dkim_selectors"] = list(dict.fromkeys(mail_security.get("dkim_selectors") or []))[:20]
    else:
        mail_security = {"enabled": False, "checks": {}, "dkim_selectors": []}

    try:
        checks, trust_stores = resolve_for_snapshot(db, tls_profile.get("checks", {})) if "tls" in selected else ({}, [])
    except TrustStoreError as error:
        raise PlanError(str(error)) from error
    return {
        "control_type": "multi" if len(selected) > 1 else selected[0],
        "definition": {"id": str(definition.id), "name": definition.name},
        "profile": {"id": str(definition.profile_id), "version_id": str(profile_version.id), "version": profile_version.version},
        "scan": scan_cfg,
        "exclusions": {"entries": [{"value": v, "scope": s} for v, s in sources.items()], "removed_targets": sorted(set(removed)), "partial_targets": sorted(set(partial))},
        "checks": checks,
        "mail_security": mail_security,
        "service_identification": service_identification,
        "quic": quic_config,
        "enabled_controls": selected,
        "ipsec": ({"ike": copy.deepcopy(ipsec_profile["ike"]), "policies": policy_bundles["ipsec"],
                    "targets": sorted({str(address) for target in targets
                                        for address in (ipaddress.ip_network(target.value, strict=False)
                                                        if target.kind == "cidr" else [target.value])
                                        if exclusions.classify_target(str(address)) != "excluded"})}
                   if "ipsec" in selected else None),
        "ssh": ({"settings": copy.deepcopy(ssh_profile), "policies": policy_bundles["ssh"],
                 "targets": sorted({str(address) for target in targets
                                     for address in (ipaddress.ip_network(target.value, strict=False)
                                                     if target.kind == "cidr" else [target.value])
                                     if exclusions.classify_target(str(address)) != "excluded"})}
                if "ssh" in selected else None),
        "trust_stores": trust_stores,
        "exposure_snapshot": exposures_snapshot,
        "passes": passes,
        "policy_mode": definition.policy_mode,
        "policies": policy_bundles["tls"],
        "tls_policies": policy_bundles["tls"],
        "export_formats": formats,
        "branding": (template.branding if template else None) or {},
    }


def fingerprint(snapshot: dict[str, Any]) -> str:
    """Hash of everything that influences observations (not the output formats nor worker count)."""
    scan = {k: v for k, v in snapshot.get("scan", {}).items() if k != "workers"}
    material = {
        "control_type": snapshot.get("control_type", "tls"),
        "enabled_controls": snapshot.get("enabled_controls", [snapshot.get("control_type", "tls")]),
        "passes": snapshot["passes"],
        "scan": scan,
        "checks": snapshot.get("checks", {}),
        "policies": [(p["name"], p["version_id"]) for p in
                     [*snapshot.get("policies", []), *((snapshot.get("ipsec") or {}).get("policies", [])), *((snapshot.get("ssh") or {}).get("policies", []))]],
        "mode": snapshot["policy_mode"],
        "ike": snapshot.get("ike", (snapshot.get("ipsec") or {}).get("ike")),
        "ipsec": snapshot.get("ipsec"),
        "ssh": snapshot.get("ssh"),
        "exposure_snapshot": snapshot.get("exposure_snapshot", []),
    }
    mail_security = snapshot.get("mail_security") or {}
    if mail_security.get("enabled"):
        material["mail_security"] = mail_security
    if (snapshot.get("service_identification") or {}).get("enabled"):
        material["service_identification"] = snapshot["service_identification"]
    if snapshot.get("quic"):
        material["quic"] = snapshot["quic"]
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
        for p in snapshot.get("tls_policies", snapshot["policies"])
    )
    job.policy_mode = snapshot["policy_mode"]
    job.scan_run_id = run_id
    return job, passes


def _safe_name(name: str) -> str:
    ascii_name = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode("ascii")  # the engine only accepts [A-Za-z0-9_-]
    cleaned = "".join(c if c.isalnum() or c in "-_" else "_" for c in ascii_name)[:60].strip("_-")
    return cleaned or "scan"
