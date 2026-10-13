"""Evolution of one scan definition between two dates, from persisted results only (nothing is re-evaluated).

For each date the reference is the **latest finished run on or before that day**; when nothing exists before the first date,
the earliest run of the window is used so that a new scan definition still has a story. The two reference runs are compared with
the existing run comparison (a target not tested in one of them is never reported as fixed).
"""
from __future__ import annotations

import uuid
from datetime import UTC, date, datetime, time
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from tls_scan_app.models import RunFinding, ScanRun
from tls_scan_app.services import comparison
from tls_scan_app.services.dashboard import IGNORED_FINDINGS, SEVERITY_RANK, rate

LEVELS = tuple(SEVERITY_RANK)  # critical, high, medium, low
MAX_LISTED = 10
MAX_SERIES = 60


def _aware(value: datetime | None) -> datetime | None:
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def _end_of_day(day: date) -> datetime:
    return datetime.combine(day, time.max, tzinfo=UTC)


def severity_counts(db: DbSession, run_ids: list[uuid.UUID]) -> dict[uuid.UUID, dict[str, dict[str, int]]]:
    """Per run and severity: distinct findings ("unique") and (finding, endpoint) occurrences. Informational items and scan errors are ignored."""
    out: dict[uuid.UUID, dict[str, dict[str, int]]] = {r: {lv: {"unique": 0, "occurrences": 0} for lv in LEVELS} for r in run_ids}
    if not run_ids:
        return out
    for f in db.execute(select(RunFinding).where(RunFinding.run_id.in_(run_ids))).scalars():
        if f.finding_id in IGNORED_FINDINGS or f.severity not in SEVERITY_RANK:
            continue
        cell = out[f.run_id][f.severity]
        cell["unique"] += 1
        cell["occurrences"] += len(f.affected_endpoint_ids or [])
    return out


def _run_info(run: ScanRun, counts: dict[str, dict[str, int]]) -> dict[str, Any]:
    s = run.summary or {}
    compliant, non_compliant = s.get("compliant_endpoints", 0), s.get("non_compliant_endpoints", 0)
    return {"run_id": str(run.id), "name": run.name, "finished_at": _aware(run.finished_at), "endpoints": s.get("total_endpoints", 0),
            "compliant": compliant, "non_compliant": non_compliant, "rate": rate(compliant, non_compliant),
            "findings": {lv: counts[lv]["occurrences"] for lv in LEVELS}}


def _compliance_moves(endpoint_changes: list[dict[str, Any]]) -> dict[str, int]:
    improved = degraded = 0
    for change in endpoint_changes:
        pair = change.get("compliance")
        if not pair:
            continue
        before, after = pair["before"][1], pair["after"][1]
        if before == "non_compliant" and after == "compliant":
            improved += 1
        elif before == "compliant" and after == "non_compliant":
            degraded += 1
    return {"improved": improved, "degraded": degraded}


def summarize_comparison(db: DbSession, old: ScanRun, new: ScanRun) -> dict[str, Any]:
    cmp = comparison.compare_runs(db, old, new)

    def top(groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
        ranked = sorted(groups, key=lambda g: (SEVERITY_RANK.get(g["severity"], 9), -len(g["affected"]), g["finding_id"]))
        return [{"finding_id": g["finding_id"], "title": g["title"], "severity": g["severity"], "endpoints": len(g["affected"])}
                for g in ranked if g["finding_id"] not in IGNORED_FINDINGS][:MAX_LISTED]

    certificates = [{"endpoint_id": c["endpoint_id"], **c["certificate"]} for c in cmp["endpoint_changes"] if "certificate" in c][:MAX_LISTED]
    return {
        "counts": cmp["counts"], "warnings": cmp["warnings"], "new": top(cmp["new"]), "fixed": top(cmp["fixed"]), "persistent": top(cmp["persistent"]),
        "endpoints_added": len(cmp["endpoints_added"]), "endpoints_removed": len(cmp["endpoints_removed"]),
        "endpoints_added_list": cmp["endpoints_added"][:MAX_LISTED], "endpoints_removed_list": cmp["endpoints_removed"][:MAX_LISTED],
        "certificate_changes": certificates, "compliance": _compliance_moves(cmp["endpoint_changes"]),
        "endpoint_changes": len(cmp["endpoint_changes"]),
    }


def between(db: DbSession, finished: list[ScanRun], definition_id: uuid.UUID | None, date_from: date, date_to: date) -> dict[str, Any]:
    """`finished` are the finished runs the caller may see (newest first)."""
    base: dict[str, Any] = {"definition_id": str(definition_id) if definition_id else None, "date_from": date_from.isoformat(), "date_to": date_to.isoformat()}
    if date_from > date_to:
        return {**base, "status": "invalid_range", "from_run": None, "to_run": None, "comparison": None, "series": []}
    runs = sorted((r for r in finished if definition_id and r.definition_id == definition_id and r.finished_at), key=lambda r: _aware(r.finished_at))
    first_day, start, end = datetime.combine(date_from, time.min, tzinfo=UTC), _end_of_day(date_from), _end_of_day(date_to)
    to_candidates = [r for r in runs if _aware(r.finished_at) <= end]
    in_window = [r for r in to_candidates if _aware(r.finished_at) >= first_day]
    to_run = to_candidates[-1] if to_candidates else None
    from_run = next((r for r in reversed(runs) if _aware(r.finished_at) <= start), None)
    if from_run is None and in_window:
        from_run = in_window[0]                      # nothing before the first date: the earliest run of the window
    series_runs = in_window[-MAX_SERIES:]
    ids = [r.id for r in {*series_runs, *(x for x in (from_run, to_run) if x)}]
    counts = severity_counts(db, ids)
    series = [_run_info(r, counts[r.id]) for r in series_runs]
    if to_run is None:
        return {**base, "status": "no_runs", "from_run": None, "to_run": None, "comparison": None, "series": series}
    result = {**base, "series": series, "to_run": _run_info(to_run, counts[to_run.id]),
              "from_run": _run_info(from_run, counts[from_run.id]) if from_run else None}
    if from_run is None or from_run.id == to_run.id:
        return {**result, "status": "single_run", "comparison": None}
    return {**result, "status": "ok", "comparison": summarize_comparison(db, from_run, to_run)}
