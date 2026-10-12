"""Comparison of two scan runs. A target not tested in one of the runs is never reported as fixed."""
from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from tls_scan_app.models import RunEndpoint, RunFinding, ScanRun

OPEN_STATUSES_EXCLUDED = {"compliant", "pass", "ok"}


def _findings(db: DbSession, run: ScanRun) -> dict[str, RunFinding]:
    return {f.finding_id: f for f in db.execute(select(RunFinding).where(RunFinding.run_id == run.id)).scalars()}


def _endpoints(db: DbSession, run: ScanRun) -> dict[str, RunEndpoint]:
    return {e.endpoint_id: e for e in db.execute(select(RunEndpoint).where(RunEndpoint.run_id == run.id)).scalars()}


def scope_of(run: ScanRun) -> set[str]:
    """Hosts actually tested in a run (scanned hosts)."""
    return set(run.scanned_hosts or [])


def _tls_check_changes(old: list[dict], new: list[dict]) -> list[dict]:
    """Status changes of the complementary checks present in both runs (a check run on one side only is not a change)."""
    old_status = {c["check_id"]: c.get("status") for c in old}
    return [{"check_id": c["check_id"], "before": old_status[c["check_id"]], "after": c.get("status")}
            for c in new if c["check_id"] in old_status and old_status[c["check_id"]] != c.get("status")]


def compare_runs(db: DbSession, old: ScanRun, new: ScanRun) -> dict[str, Any]:
    old_f, new_f = _findings(db, old), _findings(db, new)
    old_e, new_e = _endpoints(db, old), _endpoints(db, new)

    # Findings are generic ("CERTIFICATE_SELF_SIGNED") and apply to endpoints, so compare (finding, endpoint) pairs.
    def pairs(findings: dict[str, RunFinding]) -> dict[tuple[str, str], RunFinding]:
        return {(fid, ep): f for fid, f in findings.items() for ep in f.affected_endpoint_ids}

    old_p, new_p = pairs(old_f), pairs(new_f)

    def group(keys: list[tuple[str, str]], source: dict[tuple[str, str], RunFinding]) -> list[dict]:
        grouped: dict[str, dict] = {}
        for fid, ep in sorted(keys):
            f = source[(fid, ep)]
            entry = grouped.setdefault(fid, {"finding_id": fid, "title": f.title, "severity": f.severity, "affected": []})
            entry["affected"].append(ep)
        return list(grouped.values())

    new_keys = [k for k in new_p if k not in old_p]
    persistent_keys = [k for k in new_p if k in old_p]
    fixed_keys, not_retested_keys = [], []
    for key in old_p:
        if key in new_p:
            continue
        # Fixed only when that very endpoint was observed again in the new run; otherwise we simply do not know.
        (fixed_keys if key[1] in new_e else not_retested_keys).append(key)

    endpoint_changes = []
    for eid in sorted(set(old_e) & set(new_e)):
        a, b = old_e[eid], new_e[eid]
        change = {}
        if sorted(a.supported_tls_versions) != sorted(b.supported_tls_versions):
            change["tls_versions"] = {"before": a.supported_tls_versions, "after": b.supported_tls_versions}
        if sorted(a.cipher_suites) != sorted(b.cipher_suites):
            change["cipher_suites"] = {"added": sorted(set(b.cipher_suites) - set(a.cipher_suites)),
                                       "removed": sorted(set(a.cipher_suites) - set(b.cipher_suites))}
        if (a.certificate or {}).get("fingerprint") != (b.certificate or {}).get("fingerprint"):
            change["certificate"] = {"before": (a.certificate or {}).get("subject"), "after": (b.certificate or {}).get("subject"),
                                     "valid_until_before": (a.certificate or {}).get("valid_until"), "valid_until_after": (b.certificate or {}).get("valid_until")}
        if a.grade != b.grade or a.compliance_status != b.compliance_status:
            change["compliance"] = {"before": [a.grade, a.compliance_status], "after": [b.grade, b.compliance_status]}
        if b.errors and not a.errors:
            change["new_errors"] = b.errors
        tls_check_changes = _tls_check_changes(a.tls_checks or [], b.tls_checks or [])
        if tls_check_changes:
            change["tls_checks"] = tls_check_changes
        if change:
            endpoint_changes.append({"endpoint_id": eid, **change})

    warnings = []
    if old.config_snapshot.get("passes") != new.config_snapshot.get("passes"):
        warnings.append("scope_differs")
    if old.config_snapshot.get("profile", {}).get("version_id") != new.config_snapshot.get("profile", {}).get("version_id") or \
            old.config_snapshot.get("scan") != new.config_snapshot.get("scan") or old.config_snapshot.get("checks") != new.config_snapshot.get("checks"):
        warnings.append("profile_differs")
    if old.policy_versions != new.policy_versions:
        warnings.append("policy_versions_differ")
    if old.skipped_hosts or new.skipped_hosts:
        warnings.append("incomplete_runs")

    return {
        "old_run_id": str(old.id), "new_run_id": str(new.id), "warnings": warnings,
        "new": group(new_keys, new_p), "fixed": group(fixed_keys, old_p),
        "persistent": group(persistent_keys, new_p), "not_retested": group(not_retested_keys, old_p),
        "endpoints_added": sorted(set(new_e) - set(old_e)), "endpoints_removed": sorted(set(old_e) - set(new_e)),
        "endpoint_changes": endpoint_changes,
        "counts": {"new": len(new_keys), "fixed": len(fixed_keys), "persistent": len(persistent_keys), "not_retested": len(not_retested_keys)},
    }


def previous_comparable(db: DbSession, run: ScanRun) -> ScanRun | None:
    """Latest earlier finished run of the same definition and the same observation fingerprint."""
    return db.execute(
        select(ScanRun).where(
            ScanRun.definition_id == run.definition_id, ScanRun.id != run.id, ScanRun.fingerprint == run.fingerprint,
            ScanRun.status.in_(("completed", "partial")), ScanRun.finished_at < (run.finished_at or run.queued_at),
        ).order_by(ScanRun.finished_at.desc()).limit(1)
    ).scalar_one_or_none() or db.execute(
        select(ScanRun).where(
            ScanRun.definition_id == run.definition_id, ScanRun.id != run.id, ScanRun.status.in_(("completed", "partial")),
            ScanRun.finished_at < (run.finished_at or run.queued_at),
        ).order_by(ScanRun.finished_at.desc()).limit(1)
    ).scalar_one_or_none()
