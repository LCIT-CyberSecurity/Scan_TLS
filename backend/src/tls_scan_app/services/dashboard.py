"""Aggregations behind GET /api/dashboard: the current compliance picture and the compliance trend of one scan definition.

Only persisted data is read (run summaries, endpoints, findings); nothing is re-evaluated and no historical result is changed.

Current picture ("posture"):
  * basis: the latest finished run (completed or partial) of every scan definition in the caller's scope;
  * an endpoint is identified by (hostname, ip, port) and counted once, from the most recent of those runs, so two definitions
    scanning the same service do not count it twice; the same IP behind different names (SNI) stays distinct;
  * compliance rate = compliant / (compliant + non_compliant); endpoints in error or not tested are reported apart, and the rate is
    None (never 0 % or 100 %) when nothing could be evaluated;
  * findings: severity counts exclude informational ones and scan errors; "endpoints" are distinct endpoints of the basis;
  * certificates: one per fingerprint; remaining days are those measured by the scan, reduced by the time elapsed since.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from tls_scan_app.models import RunEndpoint, RunFinding, ScanDefinition, ScanRun

FINISHED = ("completed", "partial")
EXPIRY_WINDOW_DAYS = 30
TREND_POINTS = 20
VIGILANCE_LIMIT = 6
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
IGNORED_FINDINGS = {"SCAN_ERROR"}  # reliability notes, not security anomalies


def rate(compliant: int, non_compliant: int) -> float | None:
    evaluated = compliant + non_compliant
    return round(100 * compliant / evaluated, 1) if evaluated else None


def _latest_per_definition(finished: list[ScanRun]) -> list[ScanRun]:
    """`finished` is ordered newest first: keep the first run of every definition (a run without definition stands alone)."""
    seen: dict[str, ScanRun] = {}
    for run in finished:
        seen.setdefault(str(run.definition_id or run.id), run)
    return list(seen.values())


def _endpoint_key(e: RunEndpoint) -> tuple[str, str, str]:
    return (e.hostname or "", e.ip_address, e.port)


def _remaining_days(certificate: dict, finished_at: datetime | None) -> int | None:
    days = certificate.get("remaining_days")
    if not isinstance(days, int | float) or isinstance(days, bool):
        return None
    if finished_at and finished_at.tzinfo is None:
        finished_at = finished_at.replace(tzinfo=UTC)
    elapsed = (datetime.now(UTC) - finished_at).days if finished_at else 0
    return int(days) - max(0, elapsed)


def posture(db: DbSession, finished: list[ScanRun]) -> dict[str, Any]:
    basis = _latest_per_definition(finished)
    if not basis:
        return {"scans": 0, "basis_run_ids": [], "policies": [], "mixed_policies": False, "window_days": EXPIRY_WINDOW_DAYS,
                "endpoints": {"total": 0, "compliant": 0, "non_compliant": 0, "unevaluated": 0, "rate": None},
                "findings": {"critical": {"unique": 0, "endpoints": 0}, "high": {"unique": 0, "endpoints": 0}, "occurrences": 0},
                "certificates": {"expired": 0, "expiring": 0, "items": []}, "vigilance": []}
    order = {r.id: i for i, r in enumerate(basis)}  # basis is newest first: a lower index wins on duplicates
    run_by_id = {r.id: r for r in basis}
    endpoints: dict[tuple[str, str, str], RunEndpoint] = {}
    for e in sorted(db.execute(select(RunEndpoint).where(RunEndpoint.run_id.in_(run_by_id))).scalars(), key=lambda x: -order[x.run_id]):
        endpoints[_endpoint_key(e)] = e  # iterating oldest -> newest basis run: the newest overwrites
    kept_ids = {(e.run_id, e.endpoint_id) for e in endpoints.values()}
    counts = {"compliant": 0, "non_compliant": 0}
    for e in endpoints.values():
        if e.compliance_status in counts:
            counts[e.compliance_status] += 1
    total = len(endpoints)

    # findings, restricted to the endpoints kept above
    by_finding: dict[str, dict[str, Any]] = {}
    for f in db.execute(select(RunFinding).where(RunFinding.run_id.in_(run_by_id))).scalars():
        if f.finding_id in IGNORED_FINDINGS or f.severity not in SEVERITY_RANK:
            continue
        affected = {(f.run_id, eid) for eid in f.affected_endpoint_ids} & kept_ids
        if not affected:
            continue
        item = by_finding.setdefault(f.finding_id, {"finding_id": f.finding_id, "title": f.title, "category": f.category, "severity": f.severity,
                                                    "endpoints": set(), "run_id": None, "rank": 10**6})
        item["endpoints"] |= affected
        if order[f.run_id] < item["rank"]:
            item["rank"], item["run_id"] = order[f.run_id], str(f.run_id)
    findings = sorted(by_finding.values(), key=lambda i: (SEVERITY_RANK[i["severity"]], -len(i["endpoints"]), i["finding_id"]))
    severity = {level: {"unique": sum(1 for i in findings if i["severity"] == level),
                        "endpoints": len({ep for i in findings if i["severity"] == level for ep in i["endpoints"]})} for level in ("critical", "high")}
    vigilance = [{"finding_id": i["finding_id"], "title": i["title"], "category": i["category"], "severity": i["severity"],
                  "endpoints": len(i["endpoints"]), "run_id": i["run_id"]} for i in findings[:VIGILANCE_LIMIT]]

    # complementary checks that found a problem (FAIL only: not tested / inconclusive are never reported as problems)
    failed: dict[str, set] = {}
    last_run: dict[str, str] = {}
    for e in endpoints.values():
        for check in e.tls_checks or []:
            if check.get("status") == "FAIL":
                failed.setdefault(check["check_id"], set()).add((e.run_id, e.endpoint_id))
                last_run.setdefault(check["check_id"], str(e.run_id))
    room = VIGILANCE_LIMIT - len(vigilance)
    for check_id, eps in sorted(failed.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:max(0, room)]:
        vigilance.append({"finding_id": check_id, "title": check_id, "category": "complementary_check", "severity": None,
                          "endpoints": len(eps), "run_id": last_run[check_id]})

    # certificates, once per fingerprint
    certificates: dict[str, dict[str, Any]] = {}
    for e in endpoints.values():
        cert = e.certificate or {}
        days = _remaining_days(cert, run_by_id[e.run_id].finished_at)
        if days is None:
            continue
        key = cert.get("fingerprint") or f"{e.run_id}/{e.endpoint_id}"
        item = certificates.setdefault(key, {"subject": cert.get("subject") or e.hostname or e.ip_address, "valid_until": cert.get("valid_until"),
                                             "remaining_days": days, "endpoints": 0, "run_id": str(e.run_id)})
        item["endpoints"] += 1
    watched = sorted((c for c in certificates.values() if c["remaining_days"] <= EXPIRY_WINDOW_DAYS), key=lambda c: c["remaining_days"])

    policies = sorted({(p["name"], p["version"]) for r in basis for p in (r.policy_versions or [])})
    return {
        "scans": len(basis), "basis_run_ids": [str(r.id) for r in basis],
        "policies": [{"name": n, "version": v} for n, v in policies], "mixed_policies": len({tuple(sorted((p["name"], p["version"]) for p in (r.policy_versions or []))) for r in basis}) > 1,
        "window_days": EXPIRY_WINDOW_DAYS,
        "endpoints": {"total": total, **counts, "unevaluated": total - sum(counts.values()), "rate": rate(counts["compliant"], counts["non_compliant"])},
        "findings": {**severity, "occurrences": sum(len(i["endpoints"]) for i in findings if i["severity"] in ("critical", "high"))},
        "certificates": {"expired": sum(1 for c in watched if c["remaining_days"] < 0), "expiring": sum(1 for c in watched if c["remaining_days"] >= 0),
                         "items": watched[:5]},
        "vigilance": vigilance,
    }


def trend(db: DbSession, finished: list[ScanRun], definition_id: uuid.UUID | None) -> dict[str, Any]:
    """Compliance rate of the successive finished runs of ONE definition (default: the one most recently finished)."""
    definitions: dict[uuid.UUID, int] = {}
    for run in finished:
        if run.definition_id:
            definitions[run.definition_id] = definitions.get(run.definition_id, 0) + 1
    if definition_id not in definitions:
        definition_id = next((r.definition_id for r in finished if r.definition_id), None)
    names = dict(db.execute(select(ScanDefinition.id, ScanDefinition.name).where(ScanDefinition.id.in_(definitions))).all()) if definitions else {}
    runs = [r for r in reversed(finished) if r.definition_id == definition_id][-TREND_POINTS:]
    points, previous = [], None
    for run in runs:
        s = run.summary or {}
        compliant, non_compliant = s.get("compliant_endpoints", 0), s.get("non_compliant_endpoints", 0)
        signature = {"fingerprint": run.fingerprint, "policies": sorted((p["name"], p["version"]) for p in (run.policy_versions or []))}
        points.append({"run_id": str(run.id), "name": run.name, "finished_at": run.finished_at, "rate": rate(compliant, non_compliant),
                       "compliant": compliant, "non_compliant": non_compliant, "evaluated": compliant + non_compliant, "total": s.get("total_endpoints", 0),
                       "comparable": previous is None or previous == signature})
        previous = signature
    return {"definition_id": str(definition_id) if definition_id else None,
            "definitions": [{"id": str(d), "name": names.get(d, ""), "runs": n} for d, n in sorted(definitions.items(), key=lambda kv: names.get(kv[0], ""))],
            "points": points}
