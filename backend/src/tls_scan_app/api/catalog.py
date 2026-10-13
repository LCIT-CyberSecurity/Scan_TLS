"""Targets, target groups, SI / sub-SI and tags."""
from __future__ import annotations

import uuid

from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from tls_scan_app.api.common import classification_of, get_or_404, ids_matching_filter, require_modify, set_classification
from tls_scan_app.deps import get_db, require_role
from tls_scan_app.models import (
    DefinitionGroup, DnsDiscovery, DefinitionTarget, InformationSystem, ResourceSI, ResourceTag, Role, Tag, Target, TargetGroup,
    TargetDnsObservation, TargetGroupMember, User,
)
from tls_scan_app.services import audit
from tls_scan_app.services.dns_discovery import DiscoveryError, coverage, normalize_domain, policy as dns_policy, reconcile
from tls_scan_app.services.targets import TargetError, normalize_ports, normalize_target

router = APIRouter(prefix="/api", tags=["catalog"])
reader = require_role(Role.AUDITOR)
user_only = require_role(Role.USER)
operator = require_role(Role.OPERATOR)


# ---------- SI / sub-SI ----------
class SIBody(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = ""
    parent_id: uuid.UUID | None = None


def si_out(si: InformationSystem) -> dict:
    return {"id": str(si.id), "name": si.name, "description": si.description, "parent_id": str(si.parent_id) if si.parent_id else None}


@router.get("/information-systems")
def list_si(db: DbSession = Depends(get_db), _: User = Depends(reader)) -> list[dict]:
    return [si_out(s) for s in db.execute(select(InformationSystem).order_by(InformationSystem.name)).scalars()]


@router.post("/information-systems", status_code=201)
def create_si(body: SIBody, db: DbSession = Depends(get_db), user: User = Depends(user_only)) -> dict:
    if body.parent_id:
        parent = get_or_404(db, InformationSystem, body.parent_id, "Parent SI")
        if parent.parent_id:
            raise HTTPException(422, "Only one level of sub-SI is supported")
    si = InformationSystem(name=body.name.strip(), description=body.description, parent_id=body.parent_id)
    db.add(si)
    try:
        db.flush()
    except IntegrityError as error:
        db.rollback()
        raise HTTPException(409, "An SI with this name already exists here") from error
    audit.record(db, "si.create", actor=user, resource_type="si", resource_id=si.id, detail={"name": si.name})
    db.commit()
    return si_out(si)


@router.put("/information-systems/{si_id}")
def update_si(si_id: uuid.UUID, body: SIBody, db: DbSession = Depends(get_db), user: User = Depends(operator)) -> dict:
    si = get_or_404(db, InformationSystem, si_id, "SI")
    si.name, si.description = body.name.strip(), body.description
    audit.record(db, "si.update", actor=user, resource_type="si", resource_id=si.id)
    db.commit()
    return si_out(si)


@router.delete("/information-systems/{si_id}", status_code=204)
def delete_si(si_id: uuid.UUID, db: DbSession = Depends(get_db), user: User = Depends(operator)) -> None:
    si = get_or_404(db, InformationSystem, si_id, "SI")
    db.execute(delete(ResourceSI).where(ResourceSI.si_id.in_(select(InformationSystem.id).where(InformationSystem.parent_id == si.id))))
    db.execute(delete(ResourceSI).where(ResourceSI.si_id == si.id))
    db.delete(si)
    audit.record(db, "si.delete", actor=user, resource_type="si", resource_id=si_id)
    db.commit()


# ---------- tags ----------
@router.get("/tags")
def list_tags(db: DbSession = Depends(get_db), _: User = Depends(reader)) -> list[dict]:
    return [{"id": str(t.id), "name": t.name, "color": t.color} for t in db.execute(select(Tag).order_by(Tag.name)).scalars()]


@router.delete("/tags/{tag_id}", status_code=204)
def delete_tag(tag_id: uuid.UUID, db: DbSession = Depends(get_db), user: User = Depends(operator)) -> None:
    tag = get_or_404(db, Tag, tag_id, "Tag")
    db.delete(tag)
    audit.record(db, "tag.delete", actor=user, resource_type="tag", resource_id=tag_id)
    db.commit()


# ---------- targets ----------
class TargetBody(BaseModel):
    name: str = Field(default="", max_length=160)
    value: str
    ports: str = ""
    description: str = ""
    tags: list[str] | None = None
    si_ids: list[uuid.UUID] | None = None


def target_out(t: Target, cls: dict | None = None) -> dict:
    return {"id": str(t.id), "name": t.name, "value": t.value, "kind": t.kind, "ports": t.ports, "description": t.description,
            "owner_id": str(t.owner_id) if t.owner_id else None, "tags": (cls or {}).get("tags", []), "si_ids": (cls or {}).get("si", [])}


def _validated(body: TargetBody) -> tuple[str, str, str]:
    try:
        value, kind = normalize_target(body.value)
        return value, kind, normalize_ports(body.ports)
    except TargetError as error:
        raise HTTPException(422, str(error)) from error


@router.get("/targets")
def list_targets(
    q: str = "", tag: str | None = None, si: uuid.UUID | None = None, mine: bool = False,
    db: DbSession = Depends(get_db), user: User = Depends(reader),
) -> list[dict]:
    stmt = select(Target).order_by(Target.value)
    if q:
        stmt = stmt.where(or_(Target.value.ilike(f"%{q}%"), Target.name.ilike(f"%{q}%")))
    if mine:
        stmt = stmt.where(Target.owner_id == user.id)
    allowed = ids_matching_filter(db, "target", tag, si)
    if allowed is not None:
        stmt = stmt.where(Target.id.in_(allowed))
    targets = db.execute(stmt.limit(2000)).scalars().all()
    cls = classification_of(db, "target", [t.id for t in targets])
    return [target_out(t, cls[t.id]) for t in targets]


@router.post("/targets", status_code=201)
def create_target(body: TargetBody, db: DbSession = Depends(get_db), user: User = Depends(user_only)) -> dict:
    value, kind, ports = _validated(body)
    existing = db.execute(select(Target).where(Target.value == value, Target.ports == ports)).scalar_one_or_none()
    if existing:  # one record per (value, ports): reuse instead of duplicating
        raise HTTPException(409, "This target already exists")
    target = Target(name=body.name.strip(), value=value, kind=kind, ports=ports, description=body.description, owner_id=user.id)
    db.add(target)
    db.flush()
    set_classification(db, "target", target.id, body.tags, body.si_ids)
    audit.record(db, "target.create", actor=user, resource_type="target", resource_id=target.id, detail={"value": value})
    db.commit()
    return target_out(target, classification_of(db, "target", [target.id])[target.id])


@router.put("/targets/{target_id}")
def update_target(target_id: uuid.UUID, body: TargetBody, db: DbSession = Depends(get_db), user: User = Depends(user_only)) -> dict:
    target = get_or_404(db, Target, target_id, "Target")
    require_modify(user, target.owner_id)
    value, kind, ports = _validated(body)
    clash = db.execute(select(Target).where(Target.value == value, Target.ports == ports, Target.id != target.id)).scalar_one_or_none()
    if clash:
        raise HTTPException(409, "This target already exists")
    target.name, target.value, target.kind, target.ports, target.description = body.name.strip(), value, kind, ports, body.description
    set_classification(db, "target", target.id, body.tags, body.si_ids)
    audit.record(db, "target.update", actor=user, resource_type="target", resource_id=target.id)
    db.commit()
    return target_out(target, classification_of(db, "target", [target.id])[target.id])


@router.delete("/targets/{target_id}", status_code=204)
def delete_target(target_id: uuid.UUID, db: DbSession = Depends(get_db), user: User = Depends(user_only)) -> None:
    target = get_or_404(db, Target, target_id, "Target")
    require_modify(user, target.owner_id)
    if db.scalar(select(func.count()).select_from(DefinitionTarget).where(DefinitionTarget.target_id == target.id)):
        raise HTTPException(409, "The target is used by a scan definition")
    db.execute(delete(ResourceTag).where(ResourceTag.resource_type == "target", ResourceTag.resource_id == target.id))
    db.execute(delete(ResourceSI).where(ResourceSI.resource_type == "target", ResourceSI.resource_id == target.id))
    db.delete(target)
    audit.record(db, "target.delete", actor=user, resource_type="target", resource_id=target_id, detail={"value": target.value})
    db.commit()


class ImportBody(BaseModel):
    text: str = Field(description="One target per line: value[;ports[;description]]")
    tags: list[str] = []
    si_ids: list[uuid.UUID] = []


@router.post("/targets/import")
def import_targets(body: ImportBody, db: DbSession = Depends(get_db), user: User = Depends(user_only)) -> dict:
    created, existing, errors = 0, 0, []
    for number, line in enumerate(body.text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(";")]
        try:
            value, kind = normalize_target(parts[0])
            ports = normalize_ports(parts[1]) if len(parts) > 1 else ""
        except TargetError as error:
            errors.append({"line": number, "error": str(error)})
            continue
        target = db.execute(select(Target).where(Target.value == value, Target.ports == ports)).scalar_one_or_none()
        if target:
            existing += 1
        else:
            target = Target(value=value, kind=kind, ports=ports, description=parts[2] if len(parts) > 2 else "", owner_id=user.id)
            db.add(target)
            db.flush()
            created += 1
        if body.tags or body.si_ids:
            add_classification(db, target.id, body.tags, body.si_ids)
    audit.record(db, "target.import", actor=user, resource_type="target", detail={"created": created, "existing": existing, "errors": len(errors)})
    db.commit()
    return {"created": created, "existing": existing, "errors": errors}


def add_classification(db: DbSession, target_id: uuid.UUID, tags: list[str], si_ids: list[uuid.UUID]) -> None:
    current = classification_of(db, "target", [target_id])[target_id]
    set_classification(db, "target", target_id, sorted({*current["tags"], *tags}), [*map(uuid.UUID, current["si"]), *si_ids])


@router.get("/targets-export", response_class=PlainTextResponse)
def export_targets(db: DbSession = Depends(get_db), _: User = Depends(reader)) -> str:
    rows = db.execute(select(Target).order_by(Target.value)).scalars()
    return "".join(f"{t.value};{t.ports};{t.description.replace(chr(10), ' ')}\n" for t in rows)


# ---------- groups ----------
class GroupBody(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = ""
    target_ids: list[uuid.UUID] = []
    tags: list[str] | None = None
    si_ids: list[uuid.UUID] | None = None


def group_out(db: DbSession, g: TargetGroup) -> dict:
    members = [str(m) for m in db.execute(select(TargetGroupMember.target_id).where(TargetGroupMember.group_id == g.id)).scalars()]
    cls = classification_of(db, "group", [g.id])[g.id]
    return {"id": str(g.id), "name": g.name, "description": g.description, "owner_id": str(g.owner_id) if g.owner_id else None,
            "target_ids": members, "tags": cls["tags"], "si_ids": cls["si"]}


@router.get("/target-groups")
def list_groups(db: DbSession = Depends(get_db), _: User = Depends(reader)) -> list[dict]:
    return [group_out(db, g) for g in db.execute(select(TargetGroup).order_by(TargetGroup.name)).scalars()]


def _fill_group(db: DbSession, group: TargetGroup, body: GroupBody) -> None:
    db.execute(delete(TargetGroupMember).where(TargetGroupMember.group_id == group.id))
    for target_id in set(body.target_ids):
        get_or_404(db, Target, target_id, "Target")
        db.add(TargetGroupMember(group_id=group.id, target_id=target_id))
    set_classification(db, "group", group.id, body.tags, body.si_ids)


@router.post("/target-groups", status_code=201)
def create_group(body: GroupBody, db: DbSession = Depends(get_db), user: User = Depends(user_only)) -> dict:
    group = TargetGroup(name=body.name.strip(), description=body.description, owner_id=user.id)
    db.add(group)
    try:
        db.flush()
    except IntegrityError as error:
        db.rollback()
        raise HTTPException(409, "A group with this name already exists") from error
    _fill_group(db, group, body)
    audit.record(db, "group.create", actor=user, resource_type="group", resource_id=group.id)
    db.commit()
    return group_out(db, group)


@router.put("/target-groups/{group_id}")
def update_group(group_id: uuid.UUID, body: GroupBody, db: DbSession = Depends(get_db), user: User = Depends(user_only)) -> dict:
    group = get_or_404(db, TargetGroup, group_id, "Group")
    require_modify(user, group.owner_id)
    group.name, group.description = body.name.strip(), body.description
    _fill_group(db, group, body)
    audit.record(db, "group.update", actor=user, resource_type="group", resource_id=group.id)
    db.commit()
    return group_out(db, group)


@router.delete("/target-groups/{group_id}", status_code=204)
def delete_group(group_id: uuid.UUID, db: DbSession = Depends(get_db), user: User = Depends(user_only)) -> None:
    group = get_or_404(db, TargetGroup, group_id, "Group")
    require_modify(user, group.owner_id)
    if db.scalar(select(func.count()).select_from(DefinitionGroup).where(DefinitionGroup.group_id == group.id)):
        raise HTTPException(409, "The group is used by a scan definition")
    db.execute(delete(ResourceTag).where(ResourceTag.resource_type == "group", ResourceTag.resource_id == group.id))
    db.execute(delete(ResourceSI).where(ResourceSI.resource_type == "group", ResourceSI.resource_id == group.id))
    db.delete(group)
    audit.record(db, "group.delete", actor=user, resource_type="group", resource_id=group_id)
    db.commit()


# ---------- DNS discovery (OPERATOR+): several methods, then comparison with the inventory ----------
class DiscoverBody(BaseModel):
    domain: str = Field(min_length=1, max_length=253)
    authorized: bool = False  # the requester states the domain is theirs / in scope
    # V2 (all optional: a call without them behaves as before - name servers, apex records and zone transfer)
    mode: Literal["fast", "advanced"] = "fast"
    methods: list[Literal["dns", "axfr", "dictionary", "ct", "reverse"]] | None = None
    dns_server: str | None = Field(default=None, max_length=80)
    axfr_servers: list[str] = Field(default_factory=list, max_length=6)
    dictionary: Literal["small", "extended", "custom"] = "small"
    custom_words: list[str] = Field(default_factory=list, max_length=dns_policy.MAX_CUSTOM_WORDS)
    reverse: list[str] = Field(default_factory=list, max_length=16)
    timeout_seconds: int = Field(default=5, ge=1, le=30)
    concurrency: int = Field(default=20, ge=1, le=50)
    max_duration_seconds: int | None = Field(default=None, ge=30, le=900)


def _discovery_out(row: DnsDiscovery, with_result: bool = True) -> dict:
    final = row.status in ("done", "failed")
    return {"id": str(row.id), "domain": row.domain, "status": row.status, "result": row.result if (final and with_result) else None, "error": row.error,
            "created_at": row.created_at, "started_at": row.started_at, "finished_at": row.finished_at, "options": row.options,
            "progress": row.progress, "cancel_requested": row.cancel_requested}


def _own_discovery(db: DbSession, discovery_id: uuid.UUID, user: User) -> DnsDiscovery:
    row = db.get(DnsDiscovery, discovery_id)
    if row is None or (row.requested_by != user.id and user.role != Role.ADMIN):
        raise HTTPException(404, "Discovery not found")
    return row


def _discovery_options(body: DiscoverBody, settings: dict) -> dict:
    methods = list(body.methods) if body.methods is not None else list(dns_policy.LEGACY_METHODS)
    if not methods:
        raise DiscoveryError("Select at least one discovery method")
    options: dict = {"mode": body.mode, "methods": methods, "dictionary": body.dictionary, "timeout_seconds": body.timeout_seconds,
                     "concurrency": body.concurrency,
                     "max_duration_seconds": min(body.max_duration_seconds or dns_policy.MAX_DURATION[body.mode], dns_policy.MAX_DURATION["advanced"])}
    if body.mode == "fast" and (body.dns_server or body.axfr_servers or body.reverse or body.dictionary != "small" or body.custom_words):
        raise DiscoveryError("A DNS server, reverse lookups and extended dictionaries belong to the advanced mode")
    if body.dns_server:
        options["dns_server"] = dns_policy.server_key(*dns_policy.authorized_server(body.dns_server, settings))
    options["axfr_servers"] = [dns_policy.server_key(*dns_policy.authorized_server(s, settings)) for s in body.axfr_servers]
    if body.dictionary == "custom":
        options["custom_words"] = dns_policy.clean_words(body.custom_words)
        if not options["custom_words"]:
            raise DiscoveryError("The custom dictionary is empty")
    if "reverse" in methods:
        options["reverse_addresses"] = dns_policy.expand_reverse(body.reverse)
        if not options["reverse_addresses"]:
            raise DiscoveryError("Reverse DNS needs at least one IP address or network")
    elif body.reverse:
        raise DiscoveryError("Reverse addresses were given but the reverse DNS method is not selected")
    return options


@router.get("/targets/discover-config")
def discovery_config(db: DbSession = Depends(get_db), _: User = Depends(operator)) -> dict:
    """What a discovery may be pointed at (declared by an administrator) and its limits, for the wizard."""
    settings = dns_policy.load_settings(db)
    return {"allowed_servers": settings["allowed_servers"], "ct_enabled": settings["ct_enabled"],
            "limits": {"max_names": dns_policy.MAX_NAMES, "max_custom_words": dns_policy.MAX_CUSTOM_WORDS, "max_reverse_addresses": dns_policy.MAX_REVERSE_ADDRESSES,
                       "max_apply_items": reconcile.MAX_APPLY_ITEMS, "max_duration_seconds": dns_policy.MAX_DURATION}}


@router.post("/targets/discover", status_code=202)
def start_discovery(body: DiscoverBody, db: DbSession = Depends(get_db), user: User = Depends(operator)) -> dict:
    if not body.authorized:
        raise HTTPException(400, "Confirm that you are authorised to query this domain")
    try:
        domain = normalize_domain(body.domain)
        options = _discovery_options(body, dns_policy.load_settings(db))
    except DiscoveryError as error:
        raise HTTPException(422, str(error)) from None
    busy = db.scalar(select(func.count()).select_from(DnsDiscovery).where(
        DnsDiscovery.requested_by == user.id, DnsDiscovery.status.in_(("queued", "running"))))
    if busy:
        raise HTTPException(409, "A discovery is already running; wait for it to finish")
    row = DnsDiscovery(domain=domain, requested_by=user.id, options=options)
    db.add(row)
    db.flush()
    audit.record(db, "target.discover", actor=user, resource_type="dns_discovery", resource_id=row.id,
                 detail={"domain": domain, "mode": options["mode"], "methods": options["methods"], "resolver": options.get("dns_server") or "system",
                         "axfr_servers": options["axfr_servers"], "dictionary": options["dictionary"] if "dictionary" in options["methods"] else None,
                         "reverse_addresses": len(options.get("reverse_addresses", []))})
    db.commit()
    return _discovery_out(row)


def _discovery_summary(row: DnsDiscovery, names: dict) -> dict:
    result = row.result or {}
    observations = result.get("observations", [])
    return {"id": str(row.id), "domain": row.domain, "status": row.status, "error": row.error, "created_at": row.created_at, "finished_at": row.finished_at,
            "mode": (row.options or {}).get("mode", "fast"), "resolver": result.get("resolver") or ((row.options or {}).get("dns_server") or "system"),
            "methods": {k: v.get("status") for k, v in result.get("methods", {}).items()} or {m: "pending" for m in (row.options or {}).get("methods", [])},
            "names": len(observations), "in_scope": sum(1 for o in observations if o.get("in_scope")), "transfer_possible": result.get("transfer_possible", False),
            "partial": result.get("partial", False), "requested_by": names.get(row.requested_by, "")}


@router.get("/targets/discover")
def list_discoveries(db: DbSession = Depends(get_db), user: User = Depends(operator)) -> list[dict]:
    """Your discoveries (all of them for an administrator), newest first, to read their results again or import later."""
    stmt = select(DnsDiscovery).order_by(DnsDiscovery.created_at.desc()).limit(100)
    if user.role != Role.ADMIN:
        stmt = stmt.where(DnsDiscovery.requested_by == user.id)
    rows = db.execute(stmt).scalars().all()
    names = {u.id: u.email for u in db.execute(select(User).where(User.id.in_({r.requested_by for r in rows if r.requested_by}))).scalars()} if rows else {}
    return [_discovery_summary(r, names) for r in rows]


@router.delete("/targets/discover/{discovery_id}", status_code=204)
def delete_discovery(discovery_id: uuid.UUID, db: DbSession = Depends(get_db), user: User = Depends(operator)) -> None:
    """Forget a finished discovery. Targets already imported or enriched are not affected."""
    row = _own_discovery(db, discovery_id, user)
    if row.status in ("queued", "running"):
        raise HTTPException(409, "Cancel the discovery before deleting it")
    audit.record(db, "target.discover.delete", actor=user, resource_type="dns_discovery", resource_id=row.id, detail={"domain": row.domain})
    db.delete(row)
    db.commit()


@router.get("/targets/discover/{discovery_id}")
def get_discovery(discovery_id: uuid.UUID, db: DbSession = Depends(get_db), user: User = Depends(operator)) -> dict:
    return _discovery_out(_own_discovery(db, discovery_id, user))


@router.post("/targets/discover/{discovery_id}/cancel")
def cancel_discovery(discovery_id: uuid.UUID, db: DbSession = Depends(get_db), user: User = Depends(operator)) -> dict:
    row = _own_discovery(db, discovery_id, user)
    if row.status not in ("queued", "running"):
        raise HTTPException(409, "The discovery is already finished")
    row.cancel_requested = True
    if row.status == "queued":
        row.status, row.error, row.finished_at = "failed", "cancelled", datetime.now(UTC)
    audit.record(db, "target.discover.cancel", actor=user, resource_type="dns_discovery", resource_id=row.id)
    db.commit()
    return _discovery_out(row, with_result=False)


@router.get("/targets/discover/{discovery_id}/results")
def discovery_results(discovery_id: uuid.UUID, inventory: str | None = None, source: str | None = None, q: str = "", offset: int = 0,
                      limit: int = Query(100, ge=1, le=500), db: DbSession = Depends(get_db), user: User = Depends(operator)) -> dict:
    """Consolidated names of a finished discovery, compared with the Targets inventory (NEW / EXISTING / ENRICHABLE / CHANGED)."""
    row = _own_discovery(db, discovery_id, user)
    if row.status not in ("done", "failed") or not row.result:
        raise HTTPException(409, "The discovery has no result yet")
    items = reconcile.reconcile(db, row.result.get("observations", []))
    settings = dns_policy.load_settings(db)
    coverage.annotate(db, items, settings["recent_scan_days"])
    counts, sources = {}, {}
    for item in items:
        counts[item["inventory"]] = counts.get(item["inventory"], 0) + 1
        for method in item["sources"]:
            sources[method] = sources.get(method, 0) + 1
    needle = q.strip().lower()
    filtered = [i for i in items if (not inventory or i["inventory"] == inventory) and (not source or source in i["sources"])
                and (not needle or needle in i["fqdn"] or any(needle in ip for ip in i["ips"]))]
    return {"total": len(filtered), "counts": counts, "sources": sources, "offset": offset, "limit": limit, "items": filtered[offset:offset + limit],
            "methods": row.result.get("methods", {}), "nameservers": row.result.get("nameservers", []), "security": row.result.get("security", []),
            "transfer_possible": row.result.get("transfer_possible", False), "truncated": row.result.get("truncated", False),
            "partial": row.result.get("partial", False), "resolver": row.result.get("resolver", "system"),
            "recent_scan_days": settings["recent_scan_days"],
            "covered": sum(1 for i in items if i["coverage"]["covered"]), "recently_scanned": sum(1 for i in items if i["coverage"]["recently_scanned"])}


class ApplyItem(BaseModel):
    fqdn: str = Field(min_length=1, max_length=255)
    action: Literal["add", "enrich"] = "add"
    target_id: uuid.UUID | None = None   # which target to enrich when the same FQDN exists with several port settings


class NewDefinition(BaseModel):
    """A scan definition created together with the import: it scans the group the names were put in. Nothing is launched."""
    name: str = Field(min_length=1, max_length=160)
    profile_id: uuid.UUID
    policy_ids: list[uuid.UUID] = Field(min_length=1, max_length=20)
    report_template_id: uuid.UUID | None = None
    exclusions: list[str] = Field(default_factory=list, max_length=500)


class ApplyBody(BaseModel):
    items: list[ApplyItem] = Field(min_length=1, max_length=reconcile.MAX_APPLY_ITEMS)
    ports: str = ""
    tags: list[str] = Field(default_factory=list, max_length=20)
    si_ids: list[uuid.UUID] = Field(default_factory=list, max_length=20)
    group_id: uuid.UUID | None = None
    group_name: str | None = Field(default=None, max_length=120)
    dry_run: bool = False
    scan_definition_ids: list[uuid.UUID] = Field(default_factory=list, max_length=10)  # existing definitions that will scan the group
    new_definition: NewDefinition | None = None
    confirm_business_changes: bool = False   # tags / SI / group changes on targets that already exist
    on_conflict: Literal["skip", "abort"] = "skip"


@router.post("/targets/discover/{discovery_id}/apply")
def apply_discovery(discovery_id: uuid.UUID, body: ApplyBody, db: DbSession = Depends(get_db), user: User = Depends(operator)) -> dict:
    """Add the selected names as targets and/or enrich existing targets with what DNS observed. `dry_run` returns the exact plan.

    Nothing is scanned, no scan definition is touched, and no field entered by a person is overwritten.
    """
    row = _own_discovery(db, discovery_id, user)
    if row.status != "done" or not row.result:
        raise HTTPException(409, "The discovery has no usable result")
    return reconcile.apply_items(db, row, user, body)


@router.get("/targets/{target_id}/dns")
def target_dns(target_id: uuid.UUID, db: DbSession = Depends(get_db), _: User = Depends(reader)) -> dict:
    """DNS observations recorded for a target by discoveries (technical data, separate from the fields entered by hand)."""
    get_or_404(db, Target, target_id, "Target")
    return reconcile.target_observation_out(db.get(TargetDnsObservation, target_id))
