"""Targets, target groups, SI / sub-SI and tags."""
from __future__ import annotations

import uuid

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
    TargetGroupMember, User,
)
from tls_scan_app.services import audit
from tls_scan_app.services.dns_discovery import DiscoveryError, normalize_domain
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


# ---------- DNS discovery (OPERATOR+): name servers + zone-transfer attempt, run by the worker ----------
class DiscoverBody(BaseModel):
    domain: str = Field(min_length=1, max_length=253)
    authorized: bool = False  # the requester states the domain is theirs / in scope


def _discovery_out(row: DnsDiscovery) -> dict:
    return {"id": str(row.id), "domain": row.domain, "status": row.status, "result": row.result, "error": row.error,
            "created_at": row.created_at, "finished_at": row.finished_at}


@router.post("/targets/discover", status_code=202)
def start_discovery(body: DiscoverBody, db: DbSession = Depends(get_db), user: User = Depends(operator)) -> dict:
    if not body.authorized:
        raise HTTPException(400, "Confirm that you are authorised to query this domain")
    try:
        domain = normalize_domain(body.domain)
    except DiscoveryError as error:
        raise HTTPException(422, str(error)) from None
    busy = db.scalar(select(func.count()).select_from(DnsDiscovery).where(
        DnsDiscovery.requested_by == user.id, DnsDiscovery.status.in_(("queued", "running"))))
    if busy:
        raise HTTPException(409, "A discovery is already running; wait for it to finish")
    row = DnsDiscovery(domain=domain, requested_by=user.id)
    db.add(row)
    db.flush()
    audit.record(db, "target.discover", actor=user, resource_type="dns_discovery", resource_id=row.id, detail={"domain": domain})
    db.commit()
    return _discovery_out(row)


@router.get("/targets/discover/{discovery_id}")
def get_discovery(discovery_id: uuid.UUID, db: DbSession = Depends(get_db), user: User = Depends(operator)) -> dict:
    row = db.get(DnsDiscovery, discovery_id)
    if row is None or (row.requested_by != user.id and user.role != Role.ADMIN):
        raise HTTPException(404, "Discovery not found")
    return _discovery_out(row)
