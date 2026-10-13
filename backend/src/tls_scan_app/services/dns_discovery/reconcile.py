"""Comparison of a discovery with the Targets inventory, and the grouped, non-destructive import / enrichment.

Nothing here runs a scan, nothing overwrites a field a person filled in, and everything is idempotent.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from tls_scan_app.api.common import classification_of, require_modify, set_classification
from tls_scan_app.models import (
    DefinitionGroup, DefinitionPolicy, DnsDiscovery, Policy, ReportTemplate, ScanDefinition, ScanProfile, ScanSchedule, Target,
    TargetDnsObservation, TargetGroup, TargetGroupMember, User,
)
from tls_scan_app.services import audit
from tls_scan_app.services.targets import TargetError, normalize_ports, normalize_target

NEW, EXISTING, ENRICHABLE, CHANGED, OUT_OF_SCOPE = "NEW", "EXISTING", "ENRICHABLE", "CHANGED", "OUT_OF_SCOPE"
MAX_APPLY_ITEMS = 500
MAX_IPS, MAX_CNAMES, MAX_SOURCES = 50, 20, 30
CHUNK = 800
DISCOVERY_TAG = "Découverte DNS"   # practical filter only: the provenance itself is TargetDnsObservation


def default_group_name(domain: str) -> str:
    """One group per domain (no date): later discoveries of the same domain feed the same group."""
    return f"DNS — {domain}"


def _now() -> str:
    return datetime.now(UTC).isoformat()


def matches_by_fqdn(db: DbSession, fqdns: list[str]) -> dict[str, list[Target]]:
    out: dict[str, list[Target]] = {}
    for start in range(0, len(fqdns), CHUNK):
        for target in db.execute(select(Target).where(Target.kind == "fqdn", Target.value.in_(fqdns[start:start + CHUNK])).order_by(Target.ports)).scalars():
            out.setdefault(target.value, []).append(target)
    return out


def stored_for(db: DbSession, target_ids: list[uuid.UUID]) -> dict[uuid.UUID, TargetDnsObservation]:
    out: dict[uuid.UUID, TargetDnsObservation] = {}
    for start in range(0, len(target_ids), CHUNK):
        for row in db.execute(select(TargetDnsObservation).where(TargetDnsObservation.target_id.in_(target_ids[start:start + CHUNK]))).scalars():
            out[row.target_id] = row
    return out


def diff_for(stored: TargetDnsObservation | None, obs: dict[str, Any]) -> dict[str, Any]:
    known_ips = {e["ip"] for e in (stored.ips if stored else [])}
    known_cnames = {e["name"] for e in (stored.cnames if stored else [])}
    known_methods = {s["method"] for s in (stored.sources if stored else [])}
    ips, cnames = set(obs["ips"]), set(obs["cnames"])
    return {
        "new_ips": sorted(ips - known_ips), "new_cnames": sorted(cnames - known_cnames), "new_sources": sorted(set(obs["sources"]) - known_methods),
        # information only: an address not seen this time is never removed nor read as "the host is gone"
        "missing_ips": sorted(known_ips - ips) if (ips and known_ips) else [],
        "cname_changed": bool(known_cnames and cnames and cnames != known_cnames),
        "first_observation": stored is None,
    }


def status_for(diff: dict[str, Any]) -> str:
    if not diff["first_observation"] and (diff["missing_ips"] or diff["cname_changed"]):
        return CHANGED
    if diff["new_ips"] or diff["new_cnames"] or diff["new_sources"]:
        return ENRICHABLE
    return EXISTING


def reconcile(db: DbSession, observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One item per observation with its inventory status and, when the FQDN exists, the matching targets."""
    matches = matches_by_fqdn(db, [o["fqdn"] for o in observations if o["in_scope"]])
    stored = stored_for(db, [t.id for ts in matches.values() for t in ts])
    items = []
    for obs in observations:
        item = {**obs, "matches": [], "ambiguous": False, "diff": None, "inventory": OUT_OF_SCOPE if not obs["in_scope"] else NEW}
        targets = matches.get(obs["fqdn"], []) if obs["in_scope"] else []
        if targets:
            ranks = {EXISTING: 0, ENRICHABLE: 1, CHANGED: 2}
            worst, worst_diff = EXISTING, None
            for target in targets:
                diff = diff_for(stored.get(target.id), obs)
                state = status_for(diff)
                item["matches"].append({"id": str(target.id), "ports": target.ports, "name": target.name, "status": state})
                if worst_diff is None or ranks[state] > ranks[worst]:
                    worst, worst_diff = state, diff
            item["inventory"], item["diff"], item["ambiguous"] = worst, worst_diff, len(targets) > 1
        items.append(item)
    return items


def merge_observation(row: TargetDnsObservation, obs: dict[str, Any], discovery: DnsDiscovery) -> None:
    """Additive merge: values are only ever added or re-dated, never removed, and the history is bounded."""
    now = _now()
    ips = {e["ip"]: dict(e) for e in row.ips or []}
    for ip in obs["ips"]:
        entry = ips.setdefault(ip, {"ip": ip, "first_seen": now})
        entry["last_seen"] = now
    cnames = {e["name"]: dict(e) for e in row.cnames or []}
    for name in obs["cnames"]:
        entry = cnames.setdefault(name, {"name": name, "first_seen": now})
        entry["last_seen"] = now
    sources = {(s["method"], s.get("zone", "")): dict(s) for s in row.sources or []}
    for method, details in obs["source_details"].items():
        sources[(method, discovery.domain)] = {"method": method, "zone": discovery.domain, "discovery_id": str(discovery.id), "at": now,
                                                "detail": ", ".join(details[:3])}
    row.ips = sorted(ips.values(), key=lambda e: e["last_seen"], reverse=True)[:MAX_IPS]
    row.cnames = sorted(cnames.values(), key=lambda e: e["last_seen"], reverse=True)[:MAX_CNAMES]
    row.sources = sorted(sources.values(), key=lambda s: s["at"], reverse=True)[:MAX_SOURCES]
    row.last_discovery_id = discovery.id


def provenance_of(row: TargetDnsObservation | None) -> dict[str, Any] | None:
    """What a Targets list or detail needs to show where a target comes from. None for a target no discovery has seen."""
    if row is None:
        return None
    seen = [e.get(k) for e in [*(row.ips or []), *(row.cnames or [])] for k in ("first_seen", "last_seen") if e.get(k)]
    return {"domains": sorted({s.get("zone", "") for s in row.sources or [] if s.get("zone")}),
            "methods": sorted({s["method"] for s in row.sources or []}),
            "created": row.created_discovery_id is not None,
            "first_seen": min(seen) if seen else None, "last_seen": max(seen) if seen else None,
            "discovery_id": str(row.last_discovery_id) if row.last_discovery_id else None}


def target_observation_out(row: TargetDnsObservation | None) -> dict[str, Any]:
    if row is None:
        return {"ips": [], "cnames": [], "sources": [], "last_discovery_id": None, "updated_at": None, "provenance": None}
    return {"ips": row.ips, "cnames": row.cnames, "sources": row.sources,
            "last_discovery_id": str(row.last_discovery_id) if row.last_discovery_id else None, "updated_at": row.updated_at,
            "provenance": provenance_of(row)}


# ---------- grouped import / enrichment ----------
def apply_items(db: DbSession, discovery: DnsDiscovery, user: User, body: Any) -> dict[str, Any]:
    """Plan, then (unless dry_run) apply. `body` is the validated request. Returns the exact report of what was / would be done."""
    result = discovery.result or {}
    observations = {o["fqdn"]: o for o in result.get("observations", [])}
    if len(body.items) > MAX_APPLY_ITEMS:
        raise HTTPException(422, f"At most {MAX_APPLY_ITEMS} targets per operation")
    try:
        ports = normalize_ports(body.ports)
    except TargetError as error:
        raise HTTPException(422, str(error)) from error

    # group: validated before anything changes
    group: TargetGroup | None = None
    create_group = False
    if body.group_id:
        group = db.get(TargetGroup, body.group_id)
        if group is None:
            raise HTTPException(404, "Group not found")
        require_modify(user, group.owner_id)
    elif body.group_name and body.group_name.strip():
        name = body.group_name.strip()
        same_name = db.execute(select(TargetGroup).where(TargetGroup.name == name)).scalar_one_or_none()
        if same_name is not None and getattr(body, "reuse_group", False):
            require_modify(user, same_name.owner_id)
            group = same_name   # the proposed group of the domain already exists: it is fed again, never duplicated
        elif same_name is not None:
            raise HTTPException(409, f"A group named {name!r} already exists: select it instead of creating it")
        else:
            create_group = True
    tags = list(dict.fromkeys([t.strip() for t in body.tags if t.strip()] + ([DISCOVERY_TAG] if getattr(body, "discovery_tag", True) else [])))

    # scan definitions that will scan the group: validated before anything changes too
    definitions: list[ScanDefinition] = []
    new_def = getattr(body, "new_definition", None)
    wanted_ids = list(dict.fromkeys(getattr(body, "scan_definition_ids", [])))
    if wanted_ids or new_def:
        if group is None and not create_group:
            raise HTTPException(422, "A scan definition scans a group: choose or name a group first")
        for definition_id in wanted_ids:
            definition = db.get(ScanDefinition, definition_id)
            if definition is None:
                raise HTTPException(404, "Scan definition not found")
            require_modify(user, definition.owner_id)
            definitions.append(definition)
    if new_def:
        if db.get(ScanProfile, new_def.profile_id) is None:
            raise HTTPException(404, "Profile not found")
        for policy_id in new_def.policy_ids:
            if db.get(Policy, policy_id) is None:
                raise HTTPException(404, "Policy not found")
        if new_def.report_template_id and db.get(ReportTemplate, new_def.report_template_id) is None:
            raise HTTPException(404, "Report template not found")
        try:
            from tls_scanner.exclusions import parse_entries
            from tls_scanner.models import ConfigError
            new_exclusions = list(parse_entries(new_def.exclusions))
        except ConfigError as error:
            raise HTTPException(422, str(error)) from error
    scheduled = {row for row in db.execute(select(ScanSchedule.definition_id).where(ScanSchedule.active.is_(True))).scalars()}
    linked = {d.id for d in definitions if group is not None and db.get(DefinitionGroup, (d.id, group.id))}
    definition_plan = [{"id": str(d.id), "name": d.name, "action": "already" if d.id in linked else "add_group", "scheduled": d.id in scheduled}
                       for d in definitions]
    if new_def:
        definition_plan.append({"id": None, "name": new_def.name.strip(), "action": "create", "scheduled": False})

    items, seen = [], set()
    matches = matches_by_fqdn(db, [i.fqdn.strip().lower().rstrip(".") for i in body.items])
    stored = stored_for(db, [t.id for ts in matches.values() for t in ts])
    for requested in body.items:
        try:
            fqdn = normalize_target(requested.fqdn)[0]
        except TargetError as error:
            items.append({"fqdn": requested.fqdn, "outcome": "skip", "reason": "invalid", "detail": str(error)})
            continue
        if fqdn in seen:
            continue
        seen.add(fqdn)
        obs = observations.get(fqdn)
        existing = matches.get(fqdn, [])
        entry: dict[str, Any] = {"fqdn": fqdn, "action": requested.action, "outcome": "skip", "reason": "", "target_id": None, "ports": ports}
        items.append(entry)
        if obs is None:
            entry["reason"] = "not_in_discovery"
            continue
        if not obs["in_scope"]:
            entry["reason"] = "out_of_scope"   # a name met through MX/NS/CNAME/PTR/CT never widens the perimeter by itself
            continue
        target: Target | None = None
        if requested.action == "add":
            exact = next((t for t in existing if t.ports == ports), None)
            if exact:
                entry["outcome"], target = "reuse", exact
            elif existing:
                entry["reason"], entry["candidates"] = "exists_with_other_ports", [{"id": str(t.id), "ports": t.ports} for t in existing]
                continue
            else:
                entry["outcome"] = "create"
        else:
            if not existing:
                entry["reason"] = "no_target"
                continue
            if requested.target_id:
                target = next((t for t in existing if t.id == requested.target_id), None)
                if target is None:
                    entry["reason"] = "target_mismatch"
                    continue
            elif len(existing) > 1:
                entry["reason"], entry["candidates"] = "ambiguous", [{"id": str(t.id), "ports": t.ports} for t in existing]
                continue
            else:
                target = existing[0]
            entry["outcome"] = "enrich"
        if target is not None:
            entry["target_id"] = str(target.id)
            entry["dns"] = diff_for(stored.get(target.id), obs)
            entry["_target"] = target
    # business changes on EXISTING targets need an explicit confirmation (new targets are created with them)
    wants_class = bool(tags or body.si_ids or group is not None or create_group)
    existing_ids = [e["_target"].id for e in items if e["outcome"] in ("reuse", "enrich")]
    classes = classification_of(db, "target", existing_ids) if existing_ids else {}
    members = {m for m in db.execute(select(TargetGroupMember.target_id).where(TargetGroupMember.group_id == group.id)).scalars()} if group else set()
    pending_business = 0
    for entry in items:
        if entry["outcome"] in ("reuse", "enrich") and wants_class:
            current = classes[entry["_target"].id]
            added_tags = sorted(set(tags) - set(current["tags"]))
            added_si = sorted({str(s) for s in body.si_ids} - set(current["si"]))
            added_group = bool(group is not None and entry["_target"].id not in members) or create_group
            entry["business_changes"] = {"tags_added": added_tags, "si_added": added_si, "group_added": added_group,
                                         "before": {"tags": sorted(current["tags"]), "si": sorted(current["si"])}}
            if added_tags or added_si or added_group:
                pending_business += 1
    conflicts = [e for e in items if e["outcome"] == "skip"]
    summary = {
        "create": sum(e["outcome"] == "create" for e in items), "reuse": sum(e["outcome"] == "reuse" for e in items),
        "enrich": sum(e["outcome"] == "enrich" for e in items), "skipped": len(conflicts),
        "business_changes_pending_confirmation": 0 if body.confirm_business_changes else pending_business,
    }
    report = {"dry_run": body.dry_run, "applied": False, "discovery_id": str(discovery.id), "tag": DISCOVERY_TAG if DISCOVERY_TAG in tags else None,
              "summary": summary, "ports": ports, "group": {"id": str(group.id), "name": group.name} if group else
              ({"id": None, "name": body.group_name.strip(), "will_create": True} if create_group else None),
              "definitions": definition_plan,
              "items": [{k: v for k, v in e.items() if not k.startswith("_")} for e in items]}
    if body.dry_run:
        return report
    if conflicts and body.on_conflict == "abort":
        raise HTTPException(409, detail={"message": "Some targets cannot be processed; nothing was changed", "report": report})

    # --- apply: one transaction; any unexpected failure rolls everything back ---
    try:
        if create_group:
            group = TargetGroup(name=body.group_name.strip(), description=f"DNS discovery of {discovery.domain}", owner_id=user.id)
            db.add(group)
            db.flush()
            report["group"] = {"id": str(group.id), "name": group.name, "created": True}
        description = f"DNS discovery of {discovery.domain}"
        applied_definitions = []
        for definition in definitions:
            if group is not None and not db.get(DefinitionGroup, (definition.id, group.id)):
                db.add(DefinitionGroup(definition_id=definition.id, group_id=group.id))
                definition.updated_by = user.id
                applied_definitions.append({"id": str(definition.id), "name": definition.name, "action": "add_group"})
        if new_def and group is not None:
            created_def = ScanDefinition(name=new_def.name.strip(), description=f"DNS discovery of {discovery.domain}", profile_id=new_def.profile_id,
                                         report_template_id=new_def.report_template_id, exclusions=new_exclusions, owner_id=user.id, updated_by=user.id)
            db.add(created_def)
            db.flush()
            db.add(DefinitionGroup(definition_id=created_def.id, group_id=group.id))
            db.add_all([DefinitionPolicy(definition_id=created_def.id, policy_id=p) for p in set(new_def.policy_ids)])
            applied_definitions.append({"id": str(created_def.id), "name": created_def.name, "action": "create"})
            audit.record(db, "definition.create", actor=user, resource_type="definition", resource_id=created_def.id,
                         detail={"name": created_def.name, "from": "dns_discovery", "group": group.name})
        report["definitions"] = definition_plan
        for entry in items:
            if entry["outcome"] == "create":
                created = None
                try:
                    with db.begin_nested():
                        created = Target(value=entry["fqdn"], kind="fqdn", ports=ports, description=description, owner_id=user.id)
                        db.add(created)
                        db.flush()
                except IntegrityError:  # created meanwhile by someone else: reuse it
                    created = db.execute(select(Target).where(Target.value == entry["fqdn"], Target.ports == ports)).scalar_one()
                    entry["outcome"] = "reuse"
                    entry["dns"] = diff_for(stored.get(created.id), observations[entry["fqdn"]])
                entry["_target"], entry["target_id"] = created, str(created.id)
                entry["_new"] = entry["outcome"] == "create"
        classification_applied = 0
        for entry in items:
            if "_target" not in entry:
                continue
            target = entry["_target"]
            obs = observations[entry["fqdn"]]
            row = db.get(TargetDnsObservation, target.id)
            if row is None:
                row = TargetDnsObservation(target_id=target.id, ips=[], cnames=[], sources=[],
                                           created_discovery_id=discovery.id if entry.get("_new") else None)
                db.add(row)
            merge_observation(row, obs, discovery)
            if entry.get("_new") or body.confirm_business_changes:
                if tags or body.si_ids:
                    current = classification_of(db, "target", [target.id])[target.id]
                    set_classification(db, "target", target.id, sorted({*current["tags"], *tags}),
                                       [*map(uuid.UUID, current["si"]), *body.si_ids])
                    classification_applied += 1
                if group is not None and not db.get(TargetGroupMember, (group.id, target.id)):
                    db.add(TargetGroupMember(group_id=group.id, target_id=target.id))
            elif entry.get("business_changes") and any(entry["business_changes"][k] for k in ("tags_added", "si_added", "group_added")):
                entry["classification"] = "not_applied_needs_confirmation"
        summary["classification_applied"] = classification_applied
        audit.record(db, "target.discover.apply", actor=user, resource_type="dns_discovery", resource_id=discovery.id, detail={
            "domain": discovery.domain, "created": summary["create"], "reused": summary["reuse"], "enriched": summary["enrich"], "skipped": summary["skipped"],
            "group": report["group"]["name"] if report["group"] else None, "tags": tags[:10],
            "targets": [e["fqdn"] for e in items if e["outcome"] in ("create", "enrich")][:50],
            "definitions": [d["name"] for d in applied_definitions]})
        db.commit()
    except HTTPException:
        db.rollback()
        raise
    except Exception:
        db.rollback()
        raise
    report["applied"] = True
    report["items"] = [{k: v for k, v in e.items() if not k.startswith("_")} for e in items]
    return report
