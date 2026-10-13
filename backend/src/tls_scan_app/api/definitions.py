"""Scan definitions: reusable configuration (targets/groups, profile, policies, template, classification)."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session as DbSession

from tls_scan_app.api.common import classification_of, get_or_404, ids_matching_filter, require_modify, set_classification
from tls_scan_app.deps import get_db, require_role
from tls_scan_app.models import (
    DefinitionGroup, DefinitionPolicy, DefinitionTarget, Policy, ReportTemplate, Role, ScanDefinition, ScanProfile,
    ScanSchedule, Target, TargetGroup, User,
)
from tls_scan_app.services import audit, runs
from tls_scan_app.services.planner import PlanError, build_snapshot, fingerprint
from tls_scanner.exclusions import parse_entries
from tls_scanner.models import ConfigError

router = APIRouter(prefix="/api/scan-definitions", tags=["definitions"])
reader = require_role(Role.USER)  # AUDITOR only consults reports


class DefinitionBody(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    description: str = ""
    target_ids: list[uuid.UUID] = []
    group_ids: list[uuid.UUID] = []
    policy_ids: list[uuid.UUID]
    profile_id: uuid.UUID
    report_template_id: uuid.UUID | None = None
    policy_mode: str = "strict_all"
    tags: list[str] | None = None
    si_ids: list[uuid.UUID] | None = None
    exclusions: list[str] = Field(default_factory=list, max_length=500)  # IP, CIDR, FQDN or *.domain that this scan never touches


def out(db: DbSession, d: ScanDefinition) -> dict:
    cls = classification_of(db, "definition", [d.id])[d.id]
    return {
        "id": str(d.id), "name": d.name, "description": d.description, "owner_id": str(d.owner_id) if d.owner_id else None,
        "profile_id": str(d.profile_id), "report_template_id": str(d.report_template_id) if d.report_template_id else None,
        "policy_mode": d.policy_mode, "exclusions": d.exclusions or [], "tags": cls["tags"], "si_ids": cls["si"],
        "target_ids": [str(x) for x in db.execute(select(DefinitionTarget.target_id).where(DefinitionTarget.definition_id == d.id)).scalars()],
        "group_ids": [str(x) for x in db.execute(select(DefinitionGroup.group_id).where(DefinitionGroup.definition_id == d.id)).scalars()],
        "policy_ids": [str(x) for x in db.execute(select(DefinitionPolicy.policy_id).where(DefinitionPolicy.definition_id == d.id)).scalars()],
    }


def _apply(db: DbSession, d: ScanDefinition, body: DefinitionBody) -> None:
    if body.policy_mode != "strict_all":  # the only mode the engine implements
        raise HTTPException(422, "Unsupported policy_mode (supported: strict_all)")
    if not body.target_ids and not body.group_ids:
        raise HTTPException(422, "Select at least one target or group")
    if not body.policy_ids:
        raise HTTPException(422, "Select at least one policy")
    get_or_404(db, ScanProfile, body.profile_id, "Profile")
    if body.report_template_id:
        get_or_404(db, ReportTemplate, body.report_template_id, "Report template")
    for model, ids, label in ((Target, body.target_ids, "Target"), (TargetGroup, body.group_ids, "Group"), (Policy, body.policy_ids, "Policy")):
        for i in ids:
            get_or_404(db, model, i, label)
    d.name, d.description, d.profile_id = body.name.strip(), body.description, body.profile_id
    d.report_template_id, d.policy_mode = body.report_template_id, body.policy_mode
    try:
        d.exclusions = list(parse_entries(body.exclusions))
    except ConfigError as error:
        raise HTTPException(422, str(error)) from error
    for link in (DefinitionTarget, DefinitionGroup, DefinitionPolicy):
        db.execute(delete(link).where(link.definition_id == d.id))
    db.flush()
    db.add_all([DefinitionTarget(definition_id=d.id, target_id=i) for i in set(body.target_ids)])
    db.add_all([DefinitionGroup(definition_id=d.id, group_id=i) for i in set(body.group_ids)])
    db.add_all([DefinitionPolicy(definition_id=d.id, policy_id=i) for i in set(body.policy_ids)])
    set_classification(db, "definition", d.id, body.tags, body.si_ids)


@router.get("")
def list_definitions(tag: str | None = None, si: uuid.UUID | None = None, mine: bool = False,
                     db: DbSession = Depends(get_db), user: User = Depends(reader)) -> list[dict]:
    stmt = select(ScanDefinition).order_by(ScanDefinition.name)
    if mine:
        stmt = stmt.where(ScanDefinition.owner_id == user.id)
    allowed = ids_matching_filter(db, "definition", tag, si)
    if allowed is not None:
        stmt = stmt.where(ScanDefinition.id.in_(allowed))
    return [out(db, d) for d in db.execute(stmt).scalars()]


@router.get("/{definition_id}")
def get_definition(definition_id: uuid.UUID, db: DbSession = Depends(get_db), _: User = Depends(reader)) -> dict:
    return out(db, get_or_404(db, ScanDefinition, definition_id, "Scan definition"))


@router.post("", status_code=201)
def create_definition(body: DefinitionBody, db: DbSession = Depends(get_db), user: User = Depends(reader)) -> dict:
    d = ScanDefinition(name=body.name.strip(), profile_id=body.profile_id, owner_id=user.id, updated_by=user.id)
    db.add(d)
    db.flush()
    _apply(db, d, body)
    audit.record(db, "definition.create", actor=user, resource_type="definition", resource_id=d.id, detail={"name": d.name})
    db.commit()
    return out(db, d)


@router.put("/{definition_id}")
def update_definition(definition_id: uuid.UUID, body: DefinitionBody, db: DbSession = Depends(get_db), user: User = Depends(reader)) -> dict:
    d = get_or_404(db, ScanDefinition, definition_id, "Scan definition")
    require_modify(user, d.owner_id)
    d.updated_by = user.id
    _apply(db, d, body)
    audit.record(db, "definition.update", actor=user, resource_type="definition", resource_id=d.id)
    db.commit()
    return out(db, d)


@router.delete("/{definition_id}", status_code=204)
def delete_definition(definition_id: uuid.UUID, db: DbSession = Depends(get_db), user: User = Depends(reader)) -> None:
    d = get_or_404(db, ScanDefinition, definition_id, "Scan definition")
    require_modify(user, d.owner_id)
    if db.scalar(select(func.count()).select_from(ScanSchedule).where(ScanSchedule.definition_id == d.id)):
        raise HTTPException(409, "Delete the schedules of this definition first")
    audit.record(db, "definition.delete", actor=user, resource_type="definition", resource_id=d.id, detail={"name": d.name})
    db.delete(d)
    db.commit()


@router.post("/{definition_id}/run", status_code=202)
def run_definition(definition_id: uuid.UUID, request: Request, db: DbSession = Depends(get_db), user: User = Depends(reader)) -> dict:
    """Any USER can launch any definition (results are shared); modifying stays owner/operator only."""
    d = get_or_404(db, ScanDefinition, definition_id, "Scan definition")
    try:
        snapshot = build_snapshot(db, d, request.app.state.settings.max_targets_per_scan)
    except PlanError as error:
        raise HTTPException(422, str(error)) from error
    run, deduplicated = runs.create_run(db, snapshot, fingerprint(snapshot), definition=d, user=user)
    return {"run_id": str(run.id), "status": run.status, "deduplicated": deduplicated}
