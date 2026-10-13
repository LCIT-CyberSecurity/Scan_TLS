"""Trust stores (private PKI): administration (ADMIN) and the read-only selection list used by the scan profiles."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from tls_scan_app.api.common import get_or_404
from tls_scan_app.deps import get_db, require_role
from tls_scan_app.models import Role, TrustStore, TrustStoreCertificate, TrustStoreVersion, User
from tls_scan_app.models.trust import ROLE_ANCHOR
from tls_scan_app.services import audit
from tls_scan_app.services import trust_stores as svc

router = APIRouter(prefix="/api/admin/trust-stores", tags=["trust-stores"])
selection = APIRouter(prefix="/api/trust-stores", tags=["trust-stores"])
admin_only = require_role(Role.ADMIN)
reader = require_role(Role.USER)


class UploadFile(BaseModel):
    filename: str = Field(default="", max_length=255)
    content_b64: str = Field(max_length=2_000_000)


class InspectBody(BaseModel):
    files: list[UploadFile] = Field(max_length=svc.MAX_FILES_PER_IMPORT)


class CreateBody(InspectBody):
    name: str
    description: str = Field(default="", max_length=2000)
    comment: str = Field(default="", max_length=500)


class VersionBody(BaseModel):
    files: list[UploadFile] = Field(default_factory=list, max_length=svc.MAX_FILES_PER_IMPORT)
    base: str = Field(default="current", pattern="^(current|empty)$")  # keep the current certificates, or start from scratch (replace)
    remove: list[str] = Field(default_factory=list, max_length=500)  # SHA-256 fingerprints to drop from the base
    comment: str = Field(default="", max_length=500)


class UpdateBody(BaseModel):
    name: str | None = None
    description: str | None = Field(default=None, max_length=2000)
    active: bool | None = None


def _fail(error: svc.TrustStoreError) -> HTTPException:
    return HTTPException(422, str(error))


def _cert_out(row: TrustStoreCertificate) -> dict[str, Any]:
    now = datetime.now(UTC)
    not_after = datetime.fromisoformat(row.details["not_after"])
    return {"fingerprint_sha256": row.fingerprint_sha256, "role": row.role, **row.details,
            "expired": not_after < now, "expires_in_days": (not_after - now).days}


def _version_out(db: DbSession, v: TrustStoreVersion, with_certs: bool = False) -> dict[str, Any]:
    rows = svc.version_certificates(db, v.id)
    out = {"id": str(v.id), "version": v.version, "content_sha256": v.content_sha256, "comment": v.comment,
           "created_at": v.created_at, "created_by": str(v.created_by) if v.created_by else None,
           "anchor_count": sum(r.role == ROLE_ANCHOR for r in rows), "intermediate_count": sum(r.role != ROLE_ANCHOR for r in rows)}
    if with_certs:
        out["certificates"] = [_cert_out(r) for r in rows]
    return out


def _summary(db: DbSession, store: TrustStore) -> dict[str, Any]:
    version = svc.current_version(db, store.id)
    rows = svc.version_certificates(db, version.id) if version else []
    expired = any(_cert_out(r)["expired"] for r in rows)
    return {"id": str(store.id), "name": store.name, "description": store.description, "builtin": False, "type": "private",
            "active": store.active, "version": version.version if version else None,
            "certificate_count": len(rows), "anchor_count": sum(r.role == ROLE_ANCHOR for r in rows),
            "has_expired": expired, "content_sha256": version.content_sha256 if version else None,
            "updated_at": store.updated_at, "created_at": store.created_at}


def _detail(db: DbSession, store: TrustStore) -> dict[str, Any]:
    versions = db.execute(select(TrustStoreVersion).where(TrustStoreVersion.store_id == store.id)
                          .order_by(TrustStoreVersion.version.desc())).scalars().all()
    return _summary(db, store) | {
        "versions": [_version_out(db, v) for v in versions],
        "certificates": [_cert_out(r) for r in svc.version_certificates(db, versions[0].id)] if versions else [],
        "profiles": svc.profile_usage(db, store.id), "run_count": svc.run_usage_count(db, store.id),
    }


@router.get("")
def list_stores(db: DbSession = Depends(get_db), _: User = Depends(admin_only)) -> list[dict]:
    builtin = svc.builtin_public() | {"anchor_count": None, "has_expired": False}
    return [builtin] + [_summary(db, s) for s in db.execute(select(TrustStore).order_by(TrustStore.name)).scalars()]


@router.post("/inspect")
def inspect(body: InspectBody, _: User = Depends(admin_only)) -> dict:
    """Dry run of an import: shows what would be stored, or why a file is refused. Nothing is persisted."""
    return svc.inspect_files([f.model_dump() for f in body.files])


@router.post("", status_code=201)
def create_store(body: CreateBody, db: DbSession = Depends(get_db), user: User = Depends(admin_only)) -> dict:
    try:
        name = svc.validate_name(body.name)
        certs = svc.certificates_from_files([f.model_dump() for f in body.files])
        store = TrustStore(name=name, description=body.description, created_by=user.id, updated_by=user.id)
        db.add(store)
        try:
            db.flush()
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, "A trust store with this name already exists") from None
        version = svc.create_version(db, store, certs, user, body.comment)
    except svc.TrustStoreError as error:
        db.rollback()
        raise _fail(error) from error
    audit.record(db, "trust_store.create", actor=user, resource_type="trust_store", resource_id=store.id, detail={"name": name})
    audit.record(db, "trust_store.version_publish", actor=user, resource_type="trust_store", resource_id=store.id,
                 detail={"name": name, "version": version.version, "certificates": len(certs), "content_sha256": version.content_sha256})
    db.commit()
    return _detail(db, store)


@router.get("/{store_id}")
def get_store(store_id: uuid.UUID, db: DbSession = Depends(get_db), _: User = Depends(admin_only)) -> dict:
    return _detail(db, get_or_404(db, TrustStore, store_id, "Trust store"))


@router.get("/{store_id}/versions/{number}")
def get_version(store_id: uuid.UUID, number: int, db: DbSession = Depends(get_db), _: User = Depends(admin_only)) -> dict:
    get_or_404(db, TrustStore, store_id, "Trust store")
    version = db.execute(select(TrustStoreVersion).where(TrustStoreVersion.store_id == store_id, TrustStoreVersion.version == number)).scalar_one_or_none()
    if version is None:
        raise HTTPException(404, "Version not found")
    return _version_out(db, version, with_certs=True)


@router.post("/{store_id}/versions", status_code=201)
def publish_version(store_id: uuid.UUID, body: VersionBody, db: DbSession = Depends(get_db), user: User = Depends(admin_only)) -> dict:
    """New immutable version: the current certificates (or none) minus `remove`, plus the uploaded ones. Older versions stay readable."""
    store = get_or_404(db, TrustStore, store_id, "Trust store")
    try:
        kept: dict[str, Any] = {}
        current = svc.current_version(db, store.id)
        if body.base == "current" and current:
            drop = set(body.remove)
            for row, cert in zip(svc.version_certificates(db, current.id), svc.load_certificates(svc.version_certificates(db, current.id)), strict=True):
                if row.fingerprint_sha256 not in drop:
                    kept[row.fingerprint_sha256] = cert
        if not body.files and not body.remove and body.base == "current":
            raise svc.TrustStoreError("Nothing to change")
        for cert in svc.certificates_from_files([f.model_dump() for f in body.files]) if body.files else []:
            kept[svc.certificate_fingerprint(cert)] = cert
        version = svc.create_version(db, store, list(kept.values()), user, body.comment)
    except svc.TrustStoreError as error:
        db.rollback()
        raise _fail(error) from error
    store.updated_by = user.id
    store.updated_at = func.now()
    audit.record(db, "trust_store.version_publish", actor=user, resource_type="trust_store", resource_id=store.id,
                 detail={"name": store.name, "version": version.version, "certificates": len(kept), "content_sha256": version.content_sha256,
                         "replace": body.base == "empty", "removed": len(body.remove)})
    db.commit()
    return _detail(db, store)


@router.put("/{store_id}")
def update_store(store_id: uuid.UUID, body: UpdateBody, db: DbSession = Depends(get_db), user: User = Depends(admin_only)) -> dict:
    store = get_or_404(db, TrustStore, store_id, "Trust store")
    try:
        if body.name is not None and body.name.strip() != store.name:
            store.name = svc.validate_name(body.name)
    except svc.TrustStoreError as error:
        raise _fail(error) from error
    if body.description is not None:
        store.description = body.description
    if body.active is not None and body.active != store.active:
        store.active = body.active
        audit.record(db, "trust_store.activate" if body.active else "trust_store.deactivate", actor=user, resource_type="trust_store",
                     resource_id=store.id, detail={"name": store.name, "profiles": [p["name"] for p in svc.profile_usage(db, store.id)]})
    store.updated_by = user.id
    audit.record(db, "trust_store.update", actor=user, resource_type="trust_store", resource_id=store.id, detail={"name": store.name})
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "A trust store with this name already exists") from None
    return _detail(db, store)


@router.delete("/{store_id}", status_code=204)
def delete_store(store_id: uuid.UUID, db: DbSession = Depends(get_db), user: User = Depends(admin_only)) -> None:
    """Only a store that no profile and no scan ever referenced can be erased; otherwise deactivate it."""
    store = get_or_404(db, TrustStore, store_id, "Trust store")
    profiles, runs = svc.profile_usage(db, store.id), svc.run_usage_count(db, store.id)
    if profiles or runs:
        raise HTTPException(409, f"This store is referenced by {len(profiles)} profile(s) and {runs} scan(s): deactivate it instead")
    audit.record(db, "trust_store.delete", actor=user, resource_type="trust_store", resource_id=store.id, detail={"name": store.name})
    db.delete(store)
    db.commit()


@selection.get("")
def selectable_stores(db: DbSession = Depends(get_db), _: User = Depends(reader)) -> list[dict]:
    """What a profile can select (no certificate content): the built-in public store and the private stores."""
    out = [svc.builtin_public() | {"anchor_count": None}]
    for store in db.execute(select(TrustStore).order_by(TrustStore.name)).scalars():
        s = _summary(db, store)
        out.append({k: s[k] for k in ("id", "name", "description", "builtin", "type", "active", "version", "certificate_count", "anchor_count", "has_expired")})
    return out
