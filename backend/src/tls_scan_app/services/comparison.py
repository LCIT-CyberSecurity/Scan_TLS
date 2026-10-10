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


def compare_runs(db: DbSession, old: ScanRun, new: ScanRun) -> dict[str, Any]:
    old_f, new_f = _findings(db, old), _findings(db, new)
    old_e, new_e = _endpoints(db, old), _endpoints(db, new)
    tested_new = {e.ip_address for e in new_e.values()} | scope_of(new)

    def affected_hosts(f: RunFinding) -> set[str]:
        return {i.split(":")[0] for i in f.affected_endpoint_ids}

    new_findings = [f for fid, f in new_f.items() if fid not in old_f]
    persistent = [f for fid, f in new_f.items() if fid in old_f]
    fixed, not_retested = [], []
    for fid, f in old_f.items():
        if fid in new_f:
            continue
        hosts = affected_hosts(f)
        # fixed only when every affected host was effectively tested again and answered
        (fixed if hosts and hosts <= tested_new else not_retested).append(f)

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

    def brief(f: RunFinding) -> dict:
        return {"finding_id": f.finding_id, "title": f.title, "severity": f.severity, "affected": f.affected_endpoint_ids}

    return {
        "old_run_id": str(old.id), "new_run_id": str(new.id), "warnings": warnings,
        "new": [brief(f) for f in new_findings], "fixed": [brief(f) for f in fixed],
        "persistent": [brief(f) for f in persistent], "not_retested": [brief(f) for f in not_retested],
        "endpoints_added": sorted(set(new_e) - set(old_e)), "endpoints_removed": sorted(set(old_e) - set(new_e)),
        "endpoint_changes": endpoint_changes,
        "counts": {"new": len(new_findings), "fixed": len(fixed), "persistent": len(persistent), "not_retested": len(not_retested)},
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
