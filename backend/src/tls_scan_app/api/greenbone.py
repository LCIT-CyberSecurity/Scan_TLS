"""Admin-only Greenbone import API. No endpoint mutates or starts work on Greenbone."""
from __future__ import annotations

import uuid
import ipaddress
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, File, HTTPException, Request, Response, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from tls_scan_app.deps import get_db, require_role
from tls_scan_app.models import GreenboneImport, Role, SystemSetting, User
from tls_scan_app.services import audit, greenbone

router = APIRouter(prefix="/api/admin/greenbone", tags=["greenbone-import"])
admin_only = require_role(Role.ADMIN)
MAX_UPLOAD = greenbone.MAX_XML_BYTES


class ConnectionBody(BaseModel):
    name: str = Field(default="OpenVAS / Greenbone", min_length=1, max_length=160)
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=9390, ge=1, le=65535)
    username: str = Field(default="", max_length=255)
    timeout: int = Field(default=15, ge=3, le=60)


class DefinitionChoice(BaseModel):
    task_id: str = Field(min_length=1, max_length=128)
    profile_id: uuid.UUID
    policy_ids: list[uuid.UUID] = Field(min_length=1, max_length=100)


class ApplyBody(BaseModel):
    dry_run: bool = True
    selected: list[int] = Field(default_factory=list, max_length=5000)
    import_groups: bool = True
    add_tag: bool = True
    definitions: list[DefinitionChoice] = Field(default_factory=list, max_length=500)


def _config(db: DbSession) -> dict:
    row = db.get(SystemSetting, "greenbone_connection")
    defaults = {"name": "OpenVAS / Greenbone", "host": "", "port": 9390, "username": "", "timeout": 15}
    return {key: (row.value or {}).get(key, value) for key, value in defaults.items()} if row else defaults


def _out(row: GreenboneImport) -> dict:
    result = row.result
    if result and "apply_request" in result:
        result = {"pending": True}
    return {"id": str(row.id), "mode": row.mode, "source_name": row.source_name, "status": row.status,
            "created_at": row.created_at, "finished_at": row.finished_at, "error": row.error, "result": result, "progress": row.progress}


@router.get("/connection")
def get_connection(request: Request, db: DbSession = Depends(get_db), _: User = Depends(admin_only)) -> dict:
    return _config(db) | {"password_configured": bool(request.app.state.settings.greenbone_password)}


@router.put("/connection")
def put_connection(body: ConnectionBody, request: Request, db: DbSession = Depends(get_db), actor: User = Depends(admin_only)) -> dict:
    host = body.host.strip().lower().rstrip(".")
    if any(c in host for c in ("/", "\\", "@", " ")):
        raise HTTPException(422, "Saisir un nom DNS ou une adresse IP sans schéma ni port")
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        if ":" in host or "%" in host:
            raise HTTPException(422, "Adresse d’hôte invalide")
    runtime = request.app.state.settings
    allowed = {h.strip().lower().rstrip(".") for h in runtime.greenbone_allowed_hosts.split(",") if h.strip()}
    if not allowed or host not in allowed:
        raise HTTPException(422, "L’hôte doit être autorisé exactement dans TLS_SCAN_GREENBONE_ALLOWED_HOSTS côté serveur")
    value = body.model_dump() | {"host": host}
    row = db.get(SystemSetting, "greenbone_connection") or SystemSetting(key="greenbone_connection", value={})
    row.value = value
    db.add(row)
    audit.record(db, "greenbone.connection.update", actor=actor, resource_type="greenbone_connection", resource_id="greenbone",
                 detail={"host": host, "port": body.port})
    db.commit()
    return value | {"password_configured": bool(runtime.greenbone_password)}


@router.post("/test")
def test_connection(request: Request, db: DbSession = Depends(get_db), _: User = Depends(admin_only)) -> list[dict[str, str]]:
    try:
        return greenbone.test_gmp(_config(db), request.app.state.settings)
    except greenbone.GreenboneError as error:
        return [{"step": "Configuration", "status": "failed", "detail": str(error)}]


@router.post("/retrieve", status_code=202)
def retrieve(request: Request, db: DbSession = Depends(get_db), actor: User = Depends(admin_only)) -> dict:
    config = _config(db)
    if not config.get("host"):
        raise HTTPException(422, "Configurez d’abord la connexion GMP")
    row = GreenboneImport(mode="gmp", source_name=config.get("name", "Greenbone"), requested_by=actor.id,
                          snapshot={"connection": config}, status="queued")
    db.add(row)
    db.flush()
    audit.record(db, "greenbone.import.queued", actor=actor, resource_type="greenbone_import", resource_id=row.id,
                 detail={"source": config["host"], "mode": "gmp"})
    db.commit()
    return _out(row)


@router.post("/xml", status_code=201)
async def import_xml(request: Request, files: list[UploadFile] = File(...), db: DbSession = Depends(get_db), actor: User = Depends(admin_only)) -> dict:
    if len(files) > greenbone.MAX_XML_FILES:
        raise HTTPException(413, "Trop de fichiers")
    inputs = []
    total = 0
    try:
        for file in files:
            data = await file.read(MAX_UPLOAD + 1)
            total += len(data)
            if len(data) > MAX_UPLOAD or total > MAX_UPLOAD:
                raise HTTPException(413, "Taille XML maximale dépassée")
            inputs.append((file.filename or "configuration.xml", data))
        snapshot = greenbone.normalize_xml(inputs)
    except greenbone.GreenboneError as error:
        raise HTTPException(422, str(error)) from error
    row = GreenboneImport(mode="xml", source_name=snapshot["source_name"][:160], requested_by=actor.id, snapshot=snapshot,
                          status="done", finished_at=datetime.now(UTC), result={"objects": {key: len(snapshot[key]) for key in
                          ("targets", "tasks", "port_lists", "scan_configs", "schedules", "tags")}})
    db.add(row)
    db.flush()
    audit.record(db, "greenbone.import.xml_analyzed", actor=actor, resource_type="greenbone_import", resource_id=row.id,
                 detail={"files": len(inputs), "objects": row.result["objects"]})
    db.commit()
    return _out(row)


@router.get("/imports")
def imports(db: DbSession = Depends(get_db), _: User = Depends(admin_only)) -> list[dict]:
    rows = db.execute(select(GreenboneImport).order_by(GreenboneImport.created_at.desc()).limit(100)).scalars()
    return [_out(row) for row in rows]


@router.get("/imports/{import_id}")
def get_import(import_id: uuid.UUID, db: DbSession = Depends(get_db), _: User = Depends(admin_only)) -> dict:
    row = db.get(GreenboneImport, import_id)
    if row is None:
        raise HTTPException(404, "Import introuvable")
    return _out(row)


@router.get("/imports/{import_id}/preview")
def preview_import(import_id: uuid.UUID, db: DbSession = Depends(get_db), _: User = Depends(admin_only)) -> dict:
    row = db.get(GreenboneImport, import_id)
    if row is None:
        raise HTTPException(404, "Import introuvable")
    if row.status != "done" or not row.snapshot:
        raise HTTPException(409, "La récupération n’est pas terminée")
    snapshot = dict(row.snapshot)
    snapshot["import_id"] = str(row.id)
    try:
        return greenbone.preview(db, snapshot)
    except greenbone.GreenboneError as error:
        raise HTTPException(422, str(error)) from error


@router.post("/imports/{import_id}/apply")
def apply_import(import_id: uuid.UUID, body: ApplyBody, response: Response, db: DbSession = Depends(get_db), actor: User = Depends(admin_only)) -> dict:
    row = db.get(GreenboneImport, import_id)
    if row is None:
        raise HTTPException(404, "Import introuvable")
    if row.status != "done" or not row.snapshot:
        raise HTTPException(409, "La récupération n’est pas terminée")
    snapshot = dict(row.snapshot)
    snapshot["import_id"] = str(row.id)
    if body.dry_run:
        if any(index < 0 or index >= len(greenbone.normalized_targets(snapshot)) for index in body.selected):
            raise HTTPException(422, "Sélection de cible invalide")
        if any(not greenbone.normalized_targets(snapshot)[index]["importable"] for index in body.selected):
            raise HTTPException(422, "Une cible sélectionnée n’a pas de ports TCP transférables")
        planned = greenbone.preview(db, snapshot)
        try:
            definitions = greenbone.validate_definition_choices(db, snapshot, [choice.model_dump() for choice in body.definitions], body.selected)
        except greenbone.GreenboneError as error:
            raise HTTPException(422, str(error)) from error
        return {"dry_run": True, "selected": [planned["targets"][i] for i in body.selected], "summary": planned["summary"],
                "definitions": [{"task": choice["task"]["name"], "already_imported": bool(choice["existing_id"])} for choice in definitions]}
    try:
        targets = greenbone.normalized_targets(snapshot)
        if any(index < 0 or index >= len(targets) for index in body.selected):
            raise greenbone.GreenboneError("Sélection de cible invalide")
        if any(not targets[index]["importable"] for index in body.selected):
            raise greenbone.GreenboneError("Une cible sélectionnée n’a pas de ports TCP transférables")
        greenbone.validate_definition_choices(db, snapshot, [choice.model_dump() for choice in body.definitions], body.selected)
    except greenbone.GreenboneError as error:
        raise HTTPException(422, str(error)) from error
    row.status = "apply_queued"
    row.progress = {"phase": "queued"}
    row.result = {"apply_request": body.model_dump(mode="json")}
    db.commit()
    response.status_code = 202
    return _out(row)
