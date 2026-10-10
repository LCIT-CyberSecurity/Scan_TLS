from __future__ import annotations

import uuid
from typing import Any

from fastapi import HTTPException, Request
from sqlalchemy import delete, select
from sqlalchemy.orm import Session as DbSession

from tls_scan_app.models import InformationSystem, ResourceSI, ResourceTag, Role, Tag, User
from tls_scan_app.models.user import role_at_least


def get_or_404(db: DbSession, model, id_: uuid.UUID, label: str = "Resource"):
    obj = db.get(model, id_)
    if obj is None:
        raise HTTPException(404, f"{label} not found")
    return obj


def can_modify(user: User, owner_id: uuid.UUID | None) -> bool:
    """Owners modify their own objects; OPERATOR and ADMIN modify anything."""
    return role_at_least(user.role, Role.OPERATOR) or (owner_id is not None and owner_id == user.id)


def require_modify(user: User, owner_id: uuid.UUID | None) -> None:
    if not can_modify(user, owner_id):
        raise HTTPException(403, "Only the owner or an operator can modify this object")


def set_classification(db: DbSession, resource_type: str, resource_id: uuid.UUID, tags: list[str] | None, si: list[uuid.UUID] | None) -> None:
    """Replace tags (by name, created on demand) and SI links of a resource."""
    if tags is not None:
        db.execute(delete(ResourceTag).where(ResourceTag.resource_type == resource_type, ResourceTag.resource_id == resource_id))
        for name in sorted({t.strip() for t in tags if t.strip()}):
            tag = db.execute(select(Tag).where(Tag.name == name)).scalar_one_or_none()
            if tag is None:
                tag = Tag(name=name[:60])
                db.add(tag)
                db.flush()
            db.add(ResourceTag(resource_type=resource_type, resource_id=resource_id, tag_id=tag.id))
    if si is not None:
        db.execute(delete(ResourceSI).where(ResourceSI.resource_type == resource_type, ResourceSI.resource_id == resource_id))
        for si_id in set(si):
            if db.get(InformationSystem, si_id) is None:
                raise HTTPException(422, "Unknown information system")
            db.add(ResourceSI(resource_type=resource_type, resource_id=resource_id, si_id=si_id))


def classification_of(db: DbSession, resource_type: str, ids: list[uuid.UUID]) -> dict[uuid.UUID, dict[str, Any]]:
    out: dict[uuid.UUID, dict[str, Any]] = {i: {"tags": [], "si": []} for i in ids}
    if not ids:
        return out
    for rid, name in db.execute(
        select(ResourceTag.resource_id, Tag.name).join(Tag, Tag.id == ResourceTag.tag_id)
        .where(ResourceTag.resource_type == resource_type, ResourceTag.resource_id.in_(ids))
    ):
        out[rid]["tags"].append(name)
    for rid, si_id in db.execute(
        select(ResourceSI.resource_id, ResourceSI.si_id).where(ResourceSI.resource_type == resource_type, ResourceSI.resource_id.in_(ids))
    ):
        out[rid]["si"].append(str(si_id))
    return out


def ids_matching_filter(db: DbSession, resource_type: str, tag: str | None, si: uuid.UUID | None) -> set[uuid.UUID] | None:
    """Resource ids matching tag/SI filters (a SI filter includes its sub-SI); None when no filter."""
    if not tag and not si:
        return None
    result: set[uuid.UUID] | None = None
    if tag:
        found = set(db.execute(
            select(ResourceTag.resource_id).join(Tag, Tag.id == ResourceTag.tag_id)
            .where(ResourceTag.resource_type == resource_type, Tag.name == tag)).scalars())
        result = found
    if si:
        si_ids = {si, *db.execute(select(InformationSystem.id).where(InformationSystem.parent_id == si)).scalars()}
        found = set(db.execute(select(ResourceSI.resource_id).where(ResourceSI.resource_type == resource_type, ResourceSI.si_id.in_(si_ids))).scalars())
        result = found if result is None else result & found
    return result


def client_request_ip(request: Request) -> str:
    return request.client.host if request.client else ""
