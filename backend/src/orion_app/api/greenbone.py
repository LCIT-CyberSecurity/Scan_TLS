"""Admin-only Greenbone import API. No endpoint mutates or starts work on Greenbone."""
from __future__ import annotations

import uuid
import ipaddress
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, File, HTTPException, Request, Response, UploadFile
from pydantic import BaseModel, Field, SecretStr, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from orion_app.deps import get_db, require_role
from orion_app.models import GreenboneImport, Role, SystemSetting, User
from orion_app.services import audit, greenbone

router = APIRouter(prefix="/api/admin/greenbone", tags=["greenbone-import"])
admin_only = require_role(Role.ADMIN)
MAX_UPLOAD = greenbone.MAX_XML_BYTES


class ConnectionBody(BaseModel):
    name: str = Field(default="OpenVAS / Greenbone", min_length=1, max_length=160)
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=9390, ge=1, le=65535)
    username: str = Field(default="", max_length=255)
    timeout: int = Field(default=15, ge=3, le=60)
    password: SecretStr = Field(default=SecretStr(""), exclude=True)


    @field_validator("password", mode="before")
    @classmethod
    def validate_password(cls, value: object) -> object:
        if not isinstance(value, str) or len(value) > 1024:
            raise HTTPException(422, "Mot de passe GMP invalide")
        return value


class ApplyBody(BaseModel):
    dry_run: bool = True
    selected: list[int] = Field(default_factory=list, max_length=5000)


def _config(db: DbSession) -> dict:
    row = db.get(SystemSetting, "greenbone_connection")
    defaults = {"name": "OpenVAS / Greenbone", "host": "", "port": 9390, "username": "", "timeout": 15}
    return {key: (row.value or {}).get(key, value) for key, value in defaults.items()} if row else defaults


def _out(row: GreenboneImport) -> dict:
    result = row.result
    if result and "apply_request" in result:
        result = {"pending": True}
    return {"id": str(row.id), "mode": row.mode, "source_name": row.source_name, "status": row.status,
            "requested_by": str(row.requested_by) if row.requested_by else None,
            "created_at": row.created_at, "finished_at": row.finished_at, "error": row.error, "result": result, "progress": row.progress}


@router.get("/connection")
def get_connection(request: Request, db: DbSession = Depends(get_db), _: User = Depends(admin_only)) -> dict:
    config = _config(db)
    try:
        configured = bool(greenbone.connector_password(db, config, request.app.state.settings))
    except greenbone.GreenboneError:
        configured = False
    return config | {"password_configured": configured}


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
        raise HTTPException(422, "L’hôte doit être autorisé exactement dans ORION_GREENBONE_ALLOWED_HOSTS côté serveur")
    value = body.model_dump() | {"host": host}
    row = db.get(SystemSetting, "greenbone_connection") or SystemSetting(key="greenbone_connection", value={})
    previous = row.value or {}
    encrypted = previous.get("encrypted_password")
    password = body.password.get_secret_value()
    if password:
        try:
            encrypted = greenbone.credential_cipher(runtime).encrypt(password.encode()).decode("ascii")
        except greenbone.GreenboneError as error:
            raise HTTPException(503, str(error)) from None
    elif encrypted and any(previous.get(key) != value[key] for key in ("host", "port", "username")):
        raise HTTPException(422, "Saisissez le mot de passe GMP pour modifier le serveur ou le compte")
    row.value = value | ({"encrypted_password": encrypted} if encrypted else {})
    db.add(row)
    audit.record(db, "greenbone.connection.update", actor=actor, resource_type="greenbone_connection", resource_id="greenbone",
                 detail={"host": host, "port": body.port})
    db.commit()
    return get_connection(request, db, actor)


@router.post("/test")
def test_connection(request: Request, db: DbSession = Depends(get_db), _: User = Depends(admin_only)) -> list[dict[str, str]]:
    try:
        config = _config(db)
        settings = request.app.state.settings
        return greenbone.test_gmp(config, settings, password=greenbone.connector_password(db, config, settings))
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
                          status="done", finished_at=datetime.now(UTC), result={"objects": {"targets": len(snapshot["targets"])}})
    db.add(row)
    db.flush()
    audit.record(db, "greenbone.import.xml_analyzed", actor=actor, resource_type="greenbone_import", resource_id=row.id,
                 detail={"files": len(inputs), "targets": row.result["objects"]["targets"]})
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
        planned = greenbone.preview(db, snapshot)
        if any(index < 0 or index >= len(planned["targets"]) for index in body.selected):
            raise HTTPException(422, "Sélection de cible invalide")
        return {"dry_run": True, "selected": [planned["targets"][i] for i in body.selected], "summary": planned["summary"]}
    try:
        targets = greenbone.preview(db, snapshot)["targets"]
        if any(index < 0 or index >= len(targets) for index in body.selected):
            raise greenbone.GreenboneError("Sélection de cible invalide")
    except greenbone.GreenboneError as error:
        raise HTTPException(422, str(error)) from error
    row.status = "apply_queued"
    row.progress = {"phase": "queued"}
    row.result = {"apply_request": body.model_dump(mode="json")}
    db.commit()
    response.status_code = 202
    return _out(row)
