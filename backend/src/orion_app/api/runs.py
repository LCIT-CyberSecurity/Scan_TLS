"""Scan runs, schedules, reports, comparison, dashboard."""
from __future__ import annotations

import re
import uuid
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session as DbSession

from orion_app.api.common import can_modify, get_or_404, ids_matching_filter
from orion_app.deps import get_db, require_role
from orion_app.models import (
    DnsDiscovery, Role, RunEndpoint, RunFinding, RunIpsecObservation, RunSshObservation, ScanDefinition, ScanRun, ScanRunRequester, ScanSchedule,
    ScheduleTrigger, User,
)
from orion_app.models.scan import ACTIVE_STATUSES
from orion_app.models.user import role_at_least
from orion_app.services import audit, comparison, dashboard as dashboard_service, evolution as evolution_service, results, runs
from orion_app.services.schedule_calc import ScheduleError, next_after, validate
from orion_app.services.trust_stores import public_snapshot

router = APIRouter(prefix="/api", tags=["runs"])
auditor = require_role(Role.AUDITOR)
user_only = require_role(Role.USER)
MEDIA = {"html": "text/html", "md": "text/markdown", "csv": "text/csv", "findings_csv": "text/csv", "contextual_risk_csv": "text/csv", "mail_security_csv": "text/csv", "service_csv": "text/csv", "quic_csv": "text/csv", "ipsec_html": "text/html", "ipsec_md": "text/markdown", "ipsec_csv": "text/csv", "ssh_html": "text/html", "ssh_md": "text/markdown", "ssh_csv": "text/csv", "cbom": "application/json", "metadata": "application/json"}


def run_plan(snapshot: dict | None) -> dict | None:
    """What the scan checks, in a few synthetic facts for the progress panel (derived from the immutable snapshot; no secret, no certificate)."""
    if not snapshot:
        return None
    scan, checks = snapshot.get("scan") or {}, snapshot.get("checks") or {}
    certificate = checks.get("certificate") or {}
    trust = certificate.get("trust") or {}
    revocation = certificate.get("revocation") or {}
    tls = checks.get("tls") or {}
    enabled_tls = [k for k, v in tls.items() if (v is True) or (isinstance(v, dict) and v.get("enabled"))] if isinstance(tls, dict) else []
    return {
        "targets": sum(len(p.get("targets", [])) for p in snapshot.get("passes", [])), "ports": sorted({str(p.get("ports")) for p in snapshot.get("passes", [])}),
        "crypto": scan.get("crypto", "standard"),
        "certificate": certificate.get("enabled", True) is not False,
        "trust": trust.get("enabled", True) is not False,
        "public_store": (trust.get("public_store") or {}).get("enabled", True) is not False,
        "private_stores": [s.get("name") for s in (snapshot.get("trust_stores") or [])],
        "revocation": bool(revocation.get("enabled")), "tls_checks": len(enabled_tls),
        "controls": snapshot.get("enabled_controls", [snapshot.get("control_type", "tls")]),
        "quic": ({"ports": (snapshot.get("quic") or {}).get("ports", [443])} if snapshot.get("quic") else None),
        "policies": [p.get("name") for p in [*snapshot.get("policies", []), *((snapshot.get("ipsec") or {}).get("policies", [])), *((snapshot.get("ssh") or {}).get("policies", []))]], "formats": snapshot.get("export_formats", []),
        "mail_security": {"domains": (snapshot.get("mail_security") or {}).get("domains", []),
                          "checks": [key for key, enabled in ((snapshot.get("mail_security") or {}).get("checks") or {}).items() if enabled]},
    }


def run_out(r: ScanRun, detail: bool = False) -> dict:
    mail_cfg = (r.config_snapshot or {}).get("mail_security") or {}
    data = {
        "id": str(r.id), "name": r.name, "definition_id": str(r.definition_id) if r.definition_id else None,
        "schedule_id": str(r.schedule_id) if r.schedule_id else None, "initiated_by": str(r.initiated_by) if r.initiated_by else None,
        "status": r.status, "phase": r.phase, "queued_at": r.queued_at, "started_at": r.started_at, "finished_at": r.finished_at,
        "duration_seconds": r.duration_seconds, "cancel_requested": r.cancel_requested, "error": r.error,
        "progress": r.progress, "summary": r.summary, "policy_versions": r.policy_versions,
        "trust_stores": (r.config_snapshot or {}).get("trust_stores") or [],
        "control_type": (r.config_snapshot or {}).get("control_type", "tls"),
        "plan": run_plan(r.config_snapshot) if r.status in ACTIVE_STATUSES else None,
        "mail_security": ({"domains": mail_cfg.get("domains", []),
                           "checks": [key for key, enabled in (mail_cfg.get("checks") or {}).items() if enabled]}
                          if mail_cfg.get("enabled") else None),
        "exclusions": (r.config_snapshot or {}).get("exclusions"),
        "mail_security_results": r.mail_security_results or [],
        "service_observations": r.service_observations or [],
        "quic_observations": r.quic_observations or [],
        "reports": [{"format": f["format"], "size": f["size"], "sha256": f["sha256"]} for f in (r.report_files or [])],
    }
    if detail:
        data |= {"config_snapshot": public_snapshot(r.config_snapshot), "scanned_hosts": r.scanned_hosts, "skipped_hosts": r.skipped_hosts, "worker_id": r.worker_id}
    return data


def compare_discovery_results(previous: dict, current: dict) -> dict:
    """Compare observed DNS names only; absence is reported only when both result sets are complete."""
    before = {o.get("fqdn"): set(o.get("ips", [])) for o in previous.get("observations", []) if o.get("fqdn")}
    after = {o.get("fqdn"): set(o.get("ips", [])) for o in current.get("observations", []) if o.get("fqdn")}
    complete = not (previous.get("partial") or current.get("partial"))
    return {"complete": complete, "new_names": sorted(after.keys() - before.keys()),
            "not_observed": sorted(before.keys() - after.keys()) if complete else [],
            "ip_changed": [{"fqdn": name, "previous": sorted(before[name]), "current": sorted(after[name])}
                           for name in sorted(before.keys() & after.keys()) if before[name] != after[name]]}


# ---------- runs ----------
@router.get("/scan-runs")
def list_runs(mine: bool = False, status: str | None = None, definition_id: uuid.UUID | None = None, tag: str | None = None,
              si: uuid.UUID | None = None, limit: int = 100, db: DbSession = Depends(get_db), user: User = Depends(auditor)) -> list[dict]:
    stmt = results.filter_runs(select(ScanRun).order_by(ScanRun.queued_at.desc()).limit(min(limit, 500)), db, mine_of=user if mine else None,
                               status=status, definition_id=definition_id, tag=tag, si=si)
    return [run_out(r) for r in db.execute(stmt).scalars()]


@router.get("/scan-runs/{run_id}")
def get_run(run_id: uuid.UUID, db: DbSession = Depends(get_db), user: User = Depends(auditor)) -> dict:
    r = get_or_404(db, ScanRun, run_id, "Scan run")
    out = run_out(r, detail=role_at_least(user.role, Role.OPERATOR))
    endpoints = db.execute(select(RunEndpoint).where(RunEndpoint.run_id == r.id).order_by(RunEndpoint.endpoint_id)).scalars().all()
    by_value = results.endpoint_tags(db, endpoints)
    out["endpoints"] = [results.endpoint_out(e, by_value) for e in endpoints]
    out["findings"] = [results.finding_out(f) for f in db.execute(select(RunFinding).where(RunFinding.run_id == r.id)).scalars()]
    out["ipsec_observations"] = [
        {"target": x.target, "port": x.port, "status": x.status, "ike_version": x.ike_version,
         "exchange": x.exchange, "proposal": x.proposal, "verdict": x.verdict, "evidence": x.evidence}
        for x in db.execute(select(RunIpsecObservation).where(RunIpsecObservation.run_id == r.id).order_by(RunIpsecObservation.target, RunIpsecObservation.port)).scalars()
    ]
    out["ssh_observations"] = [
        {"target": x.target, "port": x.port, "status": x.status, "verdict": x.verdict, "banner": x.banner,
         "algorithms": x.algorithms, "host_keys": x.host_keys, "fingerprints": x.fingerprints, "evidence": x.evidence}
        for x in db.execute(select(RunSshObservation).where(RunSshObservation.run_id == r.id).order_by(RunSshObservation.target, RunSshObservation.port)).scalars()
    ]
    out["service_observations"] = r.service_observations or []
    out["quic_observations"] = r.quic_observations or []
    return out


@router.post("/scan-runs/{run_id}/cancel")
def cancel_run(run_id: uuid.UUID, db: DbSession = Depends(get_db), user: User = Depends(user_only)) -> dict:
    r = get_or_404(db, ScanRun, run_id, "Scan run")
    if r.status not in ACTIVE_STATUSES:
        raise HTTPException(409, "The scan is not active")
    owners = {r.initiated_by}
    if not (role_at_least(user.role, Role.OPERATOR) or user.id in owners):
        raise HTTPException(403, "Only the initiator or an operator can cancel this scan")
    runs.request_cancel(db, r, user)
    return run_out(r)


@router.delete("/scan-runs/{run_id}", status_code=204)
def delete_run(run_id: uuid.UUID, request: Request, db: DbSession = Depends(get_db), user: User = Depends(require_role(Role.OPERATOR))) -> None:
    r = get_or_404(db, ScanRun, run_id, "Scan run")
    if r.status in ACTIVE_STATUSES:
        raise HTTPException(409, "Cancel the scan first")
    root = Path(request.app.state.settings.storage_root)
    for f in r.report_files or []:
        _remove_report_tree(root, f["path"])
    audit.record(db, "scan.delete", actor=user, resource_type="scan_run", resource_id=r.id)
    db.delete(r)
    db.commit()


def _remove_report_tree(root: Path, rel: str) -> None:
    import shutil

    path = (root / rel).resolve()
    parts = Path(rel).parts
    if len(parts) >= 2 and parts[0] == "reports" and path.is_relative_to(root.resolve()):
        shutil.rmtree((root / parts[0] / parts[1]).resolve(), ignore_errors=True)


_ASSET_TAGS = (
    (re.compile(r'<link rel="stylesheet" href="(assets/css/[\w.-]+\.css)"( media="print")?>'), "style"),
    (re.compile(r'<script src="(assets/js/[\w.-]+\.js)"></script>'), "script"),
)


def inline_report_assets(text: str, base: Path) -> str:
    """The engine writes the HTML next to assets/{css,js}; served alone those relative links 404 (and the CSP forbids
    them), so the page would render unstyled and empty. Embed them to make the served report self-contained."""
    def embed(kind: str):
        def replace(m: re.Match) -> str:
            asset = (base / m.group(1)).resolve()
            if not asset.is_relative_to(base.resolve()) or not asset.is_file():
                return m.group(0)
            body = asset.read_text(encoding="utf-8").replace("</" + kind, "<\\/" + kind)
            media = ' media="print"' if kind == "style" and m.lastindex and m.lastindex > 1 and m.group(2) else ""
            return f"<{kind}{media}>{body}</{kind}>"
        return replace
    for pattern, kind in _ASSET_TAGS:
        text = pattern.sub(embed(kind), text)
    return text


@router.get("/scan-runs/{run_id}/reports/{fmt}")
def download_report(run_id: uuid.UUID, fmt: str, request: Request, inline: bool = False, db: DbSession = Depends(get_db),
                    user: User = Depends(auditor)) -> Response:
    r = get_or_404(db, ScanRun, run_id, "Scan run")
    entry = next((f for f in (r.report_files or []) if f["format"] == fmt), None)
    if entry is None:
        raise HTTPException(404, "No such report for this run")
    root = Path(request.app.state.settings.storage_root).resolve()
    path = (root / entry["path"]).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise HTTPException(404, "Report file is missing")
    import hashlib

    if hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
        audit.record(db, "report.integrity_failure", actor=user, resource_type="scan_run", resource_id=r.id, outcome="failure", detail={"format": fmt})
        db.commit()
        raise HTTPException(500, "Report integrity check failed")
    audit.record(db, "report.download", actor=user, resource_type="scan_run", resource_id=r.id, detail={"format": fmt})
    db.commit()
    headers = {"X-Content-Type-Options": "nosniff", "Content-Security-Policy": "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:; script-src 'unsafe-inline'"}
    if fmt in {"html", "ssh_html", "ipsec_html"}:
        # The report's own script renders it. Sandboxed to an opaque origin (no allow-same-origin): it cannot touch the app's cookies or API.
        headers = headers | {"Content-Security-Policy": "sandbox allow-scripts allow-modals allow-downloads; default-src 'none'; style-src 'unsafe-inline'; img-src data:; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"}
        body = inline_report_assets(path.read_text(encoding="utf-8"), path.parent)
        disposition = "inline" if inline else f'attachment; filename="{path.name}"'
        return Response(body, media_type=MEDIA.get(fmt, "text/html"), headers=headers | {"Content-Disposition": disposition})
    return FileResponse(path, media_type=MEDIA.get(fmt, "application/octet-stream"), filename=None if inline and fmt == "html" else path.name, headers=headers)


@router.get("/scan-runs/{run_id}/compare")
def compare(run_id: uuid.UUID, with_run: uuid.UUID | None = None, db: DbSession = Depends(get_db), user: User = Depends(user_only)) -> dict:
    new = get_or_404(db, ScanRun, run_id, "Scan run")
    old = get_or_404(db, ScanRun, with_run, "Scan run") if with_run else comparison.previous_comparable(db, new)
    if old is None:
        raise HTTPException(404, "No comparable earlier run")
    if old.finished_at and new.finished_at and old.finished_at > new.finished_at:
        old, new = new, old
    return comparison.compare_runs(db, old, new)


# ---------- schedules ----------
class ScheduleBody(BaseModel):
    task_type: str = "tls"
    definition_id: uuid.UUID | None = None
    kind: str
    params: dict
    timezone: str = "UTC"
    active: bool = True
    domain: str | None = None
    dns_options: dict | None = None
    authorized: bool = False


def schedule_out(db: DbSession, s: ScanSchedule, history: bool = False) -> dict:
    last = db.execute(select(ScanRun).where(ScanRun.schedule_id == s.id).order_by(ScanRun.queued_at.desc()).limit(1)).scalar_one_or_none()
    config = s.task_config or {}
    public_config = ({"domain": config.get("domain"), "options": config.get("options", {})}
                     if (s.task_type or "tls") == "dns_discovery" else None)
    d = {"id": str(s.id), "task_type": s.task_type or "tls", "task_config": public_config,
         "definition_id": str(s.definition_id) if s.definition_id else None, "owner_id": str(s.owner_id) if s.owner_id else None, "kind": s.kind,
         "params": s.params, "timezone": s.timezone, "active": s.active, "next_run_at": s.next_run_at, "last_run_at": s.last_run_at,
         "last_run": {"id": str(last.id), "status": last.status, "duration_seconds": last.duration_seconds} if last else None}
    latest_discovery_id = db.scalar(select(ScheduleTrigger.discovery_id).where(
        ScheduleTrigger.schedule_id == s.id, ScheduleTrigger.discovery_id.is_not(None)).order_by(ScheduleTrigger.due_at.desc()).limit(1))
    latest_discovery = db.get(DnsDiscovery, latest_discovery_id) if latest_discovery_id else None
    d["last_discovery"] = {"id": str(latest_discovery.id), "status": latest_discovery.status} if latest_discovery else None
    if history:
        triggers = db.execute(select(ScheduleTrigger).where(ScheduleTrigger.schedule_id == s.id).order_by(ScheduleTrigger.due_at.desc()).limit(50)).scalars().all()
        history_rows = []
        for trigger in triggers:
            discovery = db.get(DnsDiscovery, trigger.discovery_id) if trigger.discovery_id else None
            changes = None
            if discovery and discovery.status == "done" and discovery.result:
                previous = None
                for older in triggers:
                    if older.due_at >= trigger.due_at or not older.discovery_id:
                        continue
                    candidate = db.get(DnsDiscovery, older.discovery_id)
                    if candidate and candidate.status == "done" and candidate.result:
                        previous = candidate
                        break
                if previous:
                    changes = {"compared_with": str(previous.id), **compare_discovery_results(previous.result, discovery.result)}
            trigger_data = {"due_at": trigger.due_at, "outcome": trigger.outcome, "reason": trigger.reason,
                            "run_id": str(trigger.run_id) if trigger.run_id else None,
                            "discovery_id": str(trigger.discovery_id) if trigger.discovery_id else None,
                            "discovery_status": discovery.status if discovery else None, "comparison": changes}
            history_rows.append(trigger_data)
        d["triggers"] = history_rows
    return d


def _check_schedule(body: ScheduleBody, db: DbSession, user: User) -> tuple[datetime | None, dict | None]:
    try:
        validate(body.kind, body.params, body.timezone)
        nxt = next_after(body.kind, body.params, body.timezone, datetime.now(UTC))
    except (ScheduleError, ValueError) as error:
        raise HTTPException(422, str(error)) from error
    if body.task_type == "tls":
        if not body.definition_id:
            raise HTTPException(422, "A TLS schedule needs a scan definition")
        get_or_404(db, ScanDefinition, body.definition_id, "Scan definition")
        return nxt, None
    if body.task_type != "dns_discovery":
        raise HTTPException(422, "Unknown schedule task type")
    if not role_at_least(user.role, Role.OPERATOR):
        raise HTTPException(403, "DNS discovery schedules require the OPERATOR role")
    if not body.authorized:
        raise HTTPException(400, "Confirm that you are authorised to query this domain")
    if not body.domain:
        raise HTTPException(422, "A domain is required for DNS discovery")
    try:
        from orion_app.api.catalog import DiscoverBody, _discovery_options
        from orion_app.services.dns_discovery.policy import normalize_domain, load_settings

        domain = normalize_domain(body.domain)
        options = _discovery_options(DiscoverBody(domain=domain, authorized=True, **(body.dns_options or {})), load_settings(db))
    except (ValueError, TypeError) as error:
        raise HTTPException(422, str(error)) from error
    return nxt, {"domain": domain, "options": options, "authorized": True}


@router.get("/schedules")
def list_schedules(mine: bool = False, db: DbSession = Depends(get_db), user: User = Depends(user_only)) -> list[dict]:
    stmt = select(ScanSchedule).order_by(ScanSchedule.next_run_at)
    if mine or not role_at_least(user.role, Role.OPERATOR):
        # USER consults their own schedules; OPERATOR/ADMIN see all.
        stmt = stmt.where(ScanSchedule.owner_id == user.id)
    return [schedule_out(db, s) for s in db.execute(stmt).scalars()]


@router.get("/schedules/{schedule_id}")
def get_schedule(schedule_id: uuid.UUID, db: DbSession = Depends(get_db), user: User = Depends(user_only)) -> dict:
    s = get_or_404(db, ScanSchedule, schedule_id, "Schedule")
    if not can_modify(user, s.owner_id):
        raise HTTPException(403, "Not your schedule")
    return schedule_out(db, s, history=True)


@router.post("/schedules", status_code=201)
def create_schedule(body: ScheduleBody, db: DbSession = Depends(get_db), user: User = Depends(user_only)) -> dict:
    nxt, task_config = _check_schedule(body, db, user)
    s = ScanSchedule(definition_id=body.definition_id if body.task_type == "tls" else None, task_type=body.task_type,
                     task_config=task_config, owner_id=user.id, kind=body.kind, params=body.params, timezone=body.timezone,
                     active=body.active and nxt is not None, next_run_at=nxt)
    db.add(s)
    db.flush()
    audit.record(db, "schedule.create", actor=user, resource_type="schedule", resource_id=s.id, detail={"kind": s.kind, "task_type": s.task_type})
    db.commit()
    return schedule_out(db, s)


@router.put("/schedules/{schedule_id}")
def update_schedule(schedule_id: uuid.UUID, body: ScheduleBody, db: DbSession = Depends(get_db), user: User = Depends(user_only)) -> dict:
    s = get_or_404(db, ScanSchedule, schedule_id, "Schedule")
    if not can_modify(user, s.owner_id):
        raise HTTPException(403, "Only the owner or an operator can modify this schedule")
    nxt, task_config = _check_schedule(body, db, user)
    s.task_type = body.task_type
    s.definition_id = body.definition_id if body.task_type == "tls" else None
    s.task_config = task_config
    s.kind, s.params, s.timezone, s.active, s.next_run_at = body.kind, body.params, body.timezone, body.active and nxt is not None, nxt
    audit.record(db, "schedule.update", actor=user, resource_type="schedule", resource_id=s.id)
    db.commit()
    return schedule_out(db, s)


@router.delete("/schedules/{schedule_id}", status_code=204)
def delete_schedule(schedule_id: uuid.UUID, db: DbSession = Depends(get_db), user: User = Depends(user_only)) -> None:
    s = get_or_404(db, ScanSchedule, schedule_id, "Schedule")
    if not can_modify(user, s.owner_id):
        raise HTTPException(403, "Only the owner or an operator can delete this schedule")
    audit.record(db, "schedule.delete", actor=user, resource_type="schedule", resource_id=s.id)
    db.delete(s)
    db.commit()


# ---------- dashboard ----------
@router.get("/dashboard")
def dashboard(tag: str | None = None, si: uuid.UUID | None = None, scope: str = "mine", trend_definition: uuid.UUID | None = None, evolution_from: date | None = None,
              evolution_to: date | None = None, db: DbSession = Depends(get_db), user: User = Depends(auditor)) -> dict:
    stmt = select(ScanRun)
    if scope == "mine" or not role_at_least(user.role, Role.OPERATOR):
        stmt = stmt.where(or_(ScanRun.initiated_by == user.id, ScanRun.id.in_(select(ScanRunRequester.run_id).where(ScanRunRequester.user_id == user.id))))
    allowed = ids_matching_filter(db, "definition", tag, si)
    if allowed is not None:
        stmt = stmt.where(ScanRun.definition_id.in_(allowed))
    recent = db.execute(stmt.order_by(ScanRun.queued_at.desc()).limit(10)).scalars().all()
    counts = dict(db.execute(select(ScanRun.status, func.count()).where(ScanRun.id.in_(stmt.with_only_columns(ScanRun.id).order_by(None))).group_by(ScanRun.status)).all())
    finished = db.execute(stmt.where(ScanRun.status.in_(("completed", "partial")), ScanRun.summary.is_not(None)).order_by(ScanRun.finished_at.desc()).limit(200)).scalars().all()
    trend = [{"run_id": str(r.id), "name": r.name, "finished_at": r.finished_at,
              "compliant": (r.summary or {}).get("compliant_endpoints", 0), "non_compliant": (r.summary or {}).get("non_compliant_endpoints", 0)}
             for r in reversed(finished[:20])]
    upcoming = db.execute(select(ScanSchedule).where(ScanSchedule.active.is_(True), ScanSchedule.owner_id == user.id).order_by(ScanSchedule.next_run_at).limit(5)).scalars().all()
    trend_data = dashboard_service.trend(db, finished, trend_definition)
    today = datetime.now(UTC).date()
    window_to = evolution_to or today
    window_from = evolution_from or (window_to - timedelta(days=30))
    definition = uuid.UUID(trend_data["definition_id"]) if trend_data["definition_id"] else None
    return {"counts": counts, "posture": dashboard_service.posture(db, finished), "trend": trend_data, "evolution": evolution_service.between(db, finished, definition, window_from, window_to), "recent": [run_out(r) for r in recent], "compliance_trend": trend,
            "upcoming": [schedule_out(db, s) for s in upcoming]}
