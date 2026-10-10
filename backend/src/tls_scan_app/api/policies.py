"""Cryptographic policies, technical scan profiles and report templates (versioned; OPERATOR+ manage)."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import yaml
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from tls_scan_app.api.common import get_or_404
from tls_scan_app.deps import get_db, require_role
from tls_scan_app.models import Policy, PolicyVersion, ReportTemplate, Role, ScanProfile, ScanProfileVersion, User
from tls_scan_app.models.policy import ARCHIVED, DRAFT, PUBLISHED
from tls_scan_app.services import audit
from tls_scan_app.services.planner import PlanError, validate_policy_content, validate_profile_content
from tls_scanner.constants import ALLOWED_EXPORT_FORMATS

router = APIRouter(prefix="/api", tags=["policies"])
reader = require_role(Role.USER)  # AUDITOR has no use of policy internals; USER+ can consult
operator = require_role(Role.OPERATOR)


class VersionedBody(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = ""
    content: dict[str, Any]


def _kinds(kind: str):
    return (Policy, PolicyVersion, PolicyVersion.policy_id, validate_policy_content) if kind == "policies" else (
        ScanProfile, ScanProfileVersion, ScanProfileVersion.profile_id, validate_profile_content)


def _validate(validator, content):
    try:
        validator(content)
    except PlanError as error:
        raise HTTPException(422, str(error)) from error


def _fk(kind: str) -> str:
    return "policy_id" if kind == "policies" else "profile_id"


def version_out(v) -> dict:
    return {"id": str(v.id), "version": v.version, "status": v.status, "content": v.content,
            "published_at": v.published_at.isoformat() if v.published_at else None}


def item_out(db: DbSession, kind: str, item) -> dict:
    _, version_model, fk_col, _ = _kinds(kind)
    versions = db.execute(select(version_model).where(fk_col == item.id).order_by(version_model.version.desc())).scalars().all()
    return {"id": str(item.id), "name": item.name, "description": item.description, "archived": item.archived,
            "versions": [version_out(v) for v in versions]}


CREATORS: dict[str, Any] = {}


def _register(kind: str) -> None:
    model, version_model, fk_col, validator = _kinds(kind)
    fk = _fk(kind)

    @router.get(f"/{kind}", name=f"list_{kind}")
    def list_items(db: DbSession = Depends(get_db), _: User = Depends(reader)) -> list[dict]:
        return [item_out(db, kind, i) for i in db.execute(select(model).order_by(model.name)).scalars()]

    @router.post(f"/{kind}", status_code=201, name=f"create_{kind}")
    def create_item(body: VersionedBody, db: DbSession = Depends(get_db), user: User = Depends(operator)) -> dict:
        _validate(validator, body.content)
        item = model(name=body.name.strip(), description=body.description, created_by=user.id)
        db.add(item)
        try:
            db.flush()
        except IntegrityError as error:
            db.rollback()
            raise HTTPException(409, "This name is already used") from error
        db.add(version_model(**{fk: item.id}, version=1, status=DRAFT, content=body.content, created_by=user.id))
        audit.record(db, f"{kind}.create", actor=user, resource_type=kind, resource_id=item.id, detail={"name": item.name})
        db.commit()
        return item_out(db, kind, item)

    CREATORS[kind] = create_item

    @router.post(f"/{kind}/{{item_id}}/versions", status_code=201, name=f"new_version_{kind}")
    def new_version(item_id: uuid.UUID, body: VersionedBody, db: DbSession = Depends(get_db), user: User = Depends(operator)) -> dict:
        """Edit = a new draft version; published versions are never modified."""
        item = get_or_404(db, model, item_id)
        _validate(validator, body.content)
        draft = db.execute(select(version_model).where(fk_col == item.id, version_model.status == DRAFT)).scalar_one_or_none()
        if draft:
            draft.content = body.content
        else:
            last = db.scalar(select(func.max(version_model.version)).where(fk_col == item.id)) or 0
            db.add(version_model(**{fk: item.id}, version=last + 1, status=DRAFT, content=body.content, created_by=user.id))
        item.description = body.description
        audit.record(db, f"{kind}.edit", actor=user, resource_type=kind, resource_id=item.id)
        db.commit()
        return item_out(db, kind, item)

    @router.post(f"/{kind}/{{item_id}}/publish", name=f"publish_{kind}")
    def publish(item_id: uuid.UUID, db: DbSession = Depends(get_db), user: User = Depends(operator)) -> dict:
        item = get_or_404(db, model, item_id)
        draft = db.execute(select(version_model).where(fk_col == item.id, version_model.status == DRAFT)).scalar_one_or_none()
        if draft is None:
            raise HTTPException(409, "No draft version to publish")
        for old in db.execute(select(version_model).where(fk_col == item.id, version_model.status == PUBLISHED)).scalars():
            old.status = ARCHIVED
        draft.status, draft.published_at = PUBLISHED, datetime.now(UTC)
        audit.record(db, f"{kind}.publish", actor=user, resource_type=kind, resource_id=item.id, detail={"version": draft.version})
        db.commit()
        return item_out(db, kind, item)

    @router.post(f"/{kind}/{{item_id}}/duplicate", status_code=201, name=f"duplicate_{kind}")
    def duplicate(item_id: uuid.UUID, db: DbSession = Depends(get_db), user: User = Depends(operator)) -> dict:
        item = get_or_404(db, model, item_id)
        latest = db.execute(select(version_model).where(fk_col == item.id).order_by(version_model.version.desc()).limit(1)).scalar_one()
        copy = model(name=_free_name(db, model, item.name), description=item.description, created_by=user.id)
        db.add(copy)
        db.flush()
        db.add(version_model(**{fk: copy.id}, version=1, status=DRAFT, content=latest.content, created_by=user.id))
        audit.record(db, f"{kind}.duplicate", actor=user, resource_type=kind, resource_id=copy.id)
        db.commit()
        return item_out(db, kind, copy)

    @router.post(f"/{kind}/{{item_id}}/archive", name=f"archive_{kind}")
    def archive(item_id: uuid.UUID, db: DbSession = Depends(get_db), user: User = Depends(operator)) -> dict:
        item = get_or_404(db, model, item_id)
        item.archived = not item.archived
        audit.record(db, f"{kind}.archive", actor=user, resource_type=kind, resource_id=item.id, detail={"archived": item.archived})
        db.commit()
        return item_out(db, kind, item)


def _free_name(db: DbSession, model, base: str) -> str:
    n = 1
    while True:
        candidate = f"{base} (copy{'' if n == 1 else ' ' + str(n)})"
        if db.execute(select(model).where(model.name == candidate)).scalar_one_or_none() is None:
            return candidate
        n += 1


_register("policies")
_register("profiles")


# ---- YAML import / export of policies (same format as the Standalone engine) ----
class YamlBody(BaseModel):
    yaml: str


@router.post("/policies/import-yaml", status_code=201)
def import_policy_yaml(body: YamlBody, db: DbSession = Depends(get_db), user: User = Depends(operator)) -> dict:
    try:
        data = yaml.safe_load(body.yaml)
        tls = data["tls"]
        content = {k: tls[k] for k in ("allowed_versions", "allowed_cipher_algorithms", "allowed_signature_hashes", "minimum_rsa_bits")}
        name = str(data["name"])
    except (yaml.YAMLError, KeyError, TypeError) as error:
        raise HTTPException(422, f"Invalid policy YAML: {error}") from error
    return CREATORS["policies"](VersionedBody(name=name, description=str(data.get("description", "")), content=content), db, user)


@router.get("/policies/{item_id}/export-yaml", response_class=PlainTextResponse)
def export_policy_yaml(item_id: uuid.UUID, db: DbSession = Depends(get_db), _: User = Depends(reader)) -> str:
    policy = get_or_404(db, Policy, item_id)
    version = db.execute(select(PolicyVersion).where(PolicyVersion.policy_id == policy.id).order_by(PolicyVersion.version.desc()).limit(1)).scalar_one()
    return yaml.safe_dump({"name": policy.name, "version": str(version.version), "description": policy.description, "tls": version.content}, sort_keys=False)


# ---- report templates ----
class TemplateBody(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = ""
    export_formats: list[str]
    organization_name: str = ""
    accent_color: str = ""
    logo: str = ""  # data URI; kept out of list responses (only `has_logo`)


def template_out(t: ReportTemplate) -> dict:
    b = t.branding or {}
    return {"id": str(t.id), "name": t.name, "description": t.description, "export_formats": t.export_formats,
            "organization_name": b.get("organization_name", ""), "accent_color": b.get("accent_color", ""), "has_logo": bool(b.get("logo")), "logo": b.get("logo", "")}


def _branding(body: TemplateBody) -> dict:
    from tls_scan_app.services import report_branding

    try:
        return report_branding.validate({"organization_name": body.organization_name, "accent_color": body.accent_color, "logo": body.logo})
    except (report_branding.BrandingError, ValueError) as error:
        raise HTTPException(422, str(error)) from error


def _check_formats(formats: list[str]) -> None:
    if not formats or set(formats) - ALLOWED_EXPORT_FORMATS:
        raise HTTPException(422, f"export_formats must be a non-empty subset of {sorted(ALLOWED_EXPORT_FORMATS)}")


@router.get("/report-templates")
def list_templates(db: DbSession = Depends(get_db), _: User = Depends(reader)) -> list[dict]:
    return [template_out(t) for t in db.execute(select(ReportTemplate).order_by(ReportTemplate.name)).scalars()]


@router.post("/report-templates", status_code=201)
def create_template(body: TemplateBody, db: DbSession = Depends(get_db), user: User = Depends(operator)) -> dict:
    _check_formats(body.export_formats)
    template = ReportTemplate(name=body.name.strip(), description=body.description, export_formats=body.export_formats, branding=_branding(body), created_by=user.id)
    db.add(template)
    try:
        db.flush()
    except IntegrityError as error:
        db.rollback()
        raise HTTPException(409, "This name is already used") from error
    audit.record(db, "report_template.create", actor=user, resource_type="report_template", resource_id=template.id)
    db.commit()
    return template_out(template)


@router.put("/report-templates/{template_id}")
def update_template(template_id: uuid.UUID, body: TemplateBody, db: DbSession = Depends(get_db), user: User = Depends(operator)) -> dict:
    template = get_or_404(db, ReportTemplate, template_id)
    _check_formats(body.export_formats)
    template.name, template.description, template.export_formats = body.name.strip(), body.description, body.export_formats
    template.branding = _branding(body)
    audit.record(db, "report_template.update", actor=user, resource_type="report_template", resource_id=template.id)
    db.commit()
    return template_out(template)


@router.delete("/report-templates/{template_id}", status_code=204)
def delete_template(template_id: uuid.UUID, db: DbSession = Depends(get_db), user: User = Depends(operator)) -> None:
    template = get_or_404(db, ReportTemplate, template_id)
    db.delete(template)
    audit.record(db, "report_template.delete", actor=user, resource_type="report_template", resource_id=template_id)
    db.commit()
