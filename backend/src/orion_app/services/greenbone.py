"""Read-only Greenbone extraction and the shared normalized import model."""
from __future__ import annotations

from pathlib import Path

import hashlib
import ipaddress
import logging
import ssl
import socket
import xml.etree.ElementTree as ET
from typing import Any

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException

from orion_app.models import GreenboneImport

logger = logging.getLogger("orion_app.greenbone")
MAX_XML_BYTES = 10 * 1024 * 1024
MAX_XML_FILES = 20
MAX_OBJECTS = 20_000
MAX_NORMALIZED_TARGETS = 5_000
PAGE_SIZE = 500


class GreenboneError(ValueError):
    pass


def _text(node: ET.Element, path: str, default: str = "") -> str:
    found = node.find(path)
    return (found.text or "").strip() if found is not None else default


def _id(node: ET.Element) -> str:
    return node.get("id", "").strip()


def _version(response: Any) -> str:
    if isinstance(response, str):
        return response
    return _text(response, "version") or _text(response, "protocol_version") or "unknown"


def _parse_document(data: bytes) -> ET.Element:
    if len(data) > MAX_XML_BYTES:
        raise GreenboneError(f"Fichier XML trop volumineux (limite {MAX_XML_BYTES // (1024 * 1024)} Mio)")
    try:
        root = ElementTree.fromstring(data)
    except (ET.ParseError, DefusedXmlException, ValueError) as error:
        raise GreenboneError("XML invalide ou interdit") from error
    stack = [(root, 1)]
    node_count = 0
    while stack:
        node, depth = stack.pop()
        node_count += 1
        if depth > 64 or node_count > 500_000:
            raise GreenboneError("Structure XML trop profonde ou volumineuse")
        stack.extend((child, depth + 1) for child in node)
    if root.tag != "get_targets_response":
        raise GreenboneError("Seul un export GMP get_targets_response est accepté")
    status = root.get("status")
    if status is not None and status != "200":
        raise GreenboneError(f"Réponse GMP en erreur (statut {status})")
    return root


def _target(node: ET.Element) -> dict[str, Any]:
    hosts = [h.strip() for h in _text(node, "hosts").replace(",", " ").split() if h.strip()]
    return {"id": _id(node), "name": _text(node, "name"), "comment": _text(node, "comment"), "hosts": hosts}


def normalize_xml(files: list[tuple[str, bytes]]) -> dict[str, Any]:
    if not files or len(files) > MAX_XML_FILES:
        raise GreenboneError(f"Fournir entre 1 et {MAX_XML_FILES} fichiers XML")
    total = sum(len(data) for _, data in files)
    if total > MAX_XML_BYTES:
        raise GreenboneError(f"Taille totale XML supérieure à {MAX_XML_BYTES // (1024 * 1024)} Mio")
    normalized: dict[str, list[dict[str, Any]]] = {"targets": []}
    for filename, data in files:
        root = _parse_document(data)
        key = "targets"
        for node in root:
            if node.tag != "target":
                continue
            normalized[key].append(_target(node))
            if sum(map(len, normalized.values())) > MAX_OBJECTS:
                raise GreenboneError(f"Trop d’objets XML (limite {MAX_OBJECTS})")
    source_names = sorted(name.strip().replace("\\", "/").rsplit("/", 1)[-1].casefold() for name, _ in files)
    source_id = "xml:" + hashlib.sha256("\0".join(source_names).encode()).hexdigest()[:32]
    return {"source_id": source_id, "source_name": ", ".join(name[:100] for name, _ in files), "mode": "xml", **normalized}


def _xml_bytes(response: Any) -> bytes:
    return ET.tostring(response, encoding="utf-8")


def _paginate_targets(method: Any, *, maximum: int = MAX_OBJECTS) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for offset in range(0, maximum, PAGE_SIZE):
        options = {"filter_string": f"rows={PAGE_SIZE} first={offset + 1}"}
        response = method(**options)
        root = ElementTree.fromstring(_xml_bytes(response))
        page = root.findall("target")
        rows.extend(_target(node) for node in page)
        if len(page) < PAGE_SIZE:
            return rows
    raise GreenboneError(f"Limite de {maximum} objets atteinte ; récupération potentiellement partielle")


def credential_cipher(settings: Any):
    """Read the deployment key separately from the encrypted database setting."""
    import base64
    from cryptography.fernet import Fernet

    try:
        key = bytes.fromhex(Path(settings.greenbone_credential_key_file).read_text().strip())
        return Fernet(base64.urlsafe_b64encode(key))
    except (OSError, ValueError):
        raise GreenboneError("Clé de chiffrement GMP indisponible ou invalide") from None


def connector_password(db: Any, config: dict, settings: Any) -> str:
    from cryptography.fernet import InvalidToken
    from orion_app.models import SystemSetting

    row = db.get(SystemSetting, "greenbone_connection", populate_existing=True)
    stored = row.value if row else {}
    encrypted = stored.get("encrypted_password")
    if not encrypted:
        return settings.greenbone_password
    if any(config.get(field) != stored.get(field) for field in ("host", "port", "username")):
        raise GreenboneError("La connexion GMP a changé. Relancez la récupération.")
    try:
        return credential_cipher(settings).decrypt(encrypted.encode("ascii")).decode()
    except (InvalidToken, UnicodeError):
        raise GreenboneError("Mot de passe GMP enregistré illisible") from None


def retrieve_gmp(config: dict[str, Any], settings: Any, progress=lambda _: None, *, password: str | None = None) -> dict[str, Any]:
    host = config["host"].strip().lower().rstrip(".")
    allowed = {value.strip().lower().rstrip(".") for value in settings.greenbone_allowed_hosts.split(",") if value.strip()}
    if not allowed or host not in allowed:
        raise GreenboneError("Hôte refusé : configurez son nom exact dans ORION_GREENBONE_ALLOWED_HOSTS")
    username = settings.greenbone_username or config.get("username", "")
    password = settings.greenbone_password if password is None else password
    if not username or not password:
        raise GreenboneError("Identifiants GMP absents (ORION_GREENBONE_USERNAME et mot de passe/fichier secret)")
    try:
        from gvm.connections import TLSConnection
        from gvm.protocols.gmp import GMP
        from gvm.transforms import EtreeCheckCommandTransform
    except ImportError as error:
        raise GreenboneError("La dépendance python-gvm n’est pas installée") from error
    try:
        answers = socket.getaddrinfo(host, config["port"], type=socket.SOCK_STREAM)
    except OSError as error:
        raise GreenboneError(f"DNS : résolution impossible ({type(error).__name__})") from error
    if not answers:
        raise GreenboneError("DNS : aucune adresse retournée")
    for answer in answers:
        address = ipaddress.ip_address(answer[4][0])
        if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
            raise GreenboneError("Adresse résolue refusée par la politique de sécurité GMP")
    ca = settings.greenbone_ca_file or None
    cert = settings.greenbone_client_cert_file or None
    key = settings.greenbone_client_key_file or None
    source_id = f"gmp:{host}:{config['port']}"
    try:
        connection = TLSConnection(hostname=host, port=config["port"], cafile=ca, certfile=cert, keyfile=key, timeout=config["timeout"])
        with GMP(connection=connection, transform=EtreeCheckCommandTransform()) as gmp:
            version = _version(gmp.get_version())
            gmp.authenticate(username, password)
            progress({"phase": "targets"})
            targets = _paginate_targets(gmp.get_targets)
    except Exception as error:  # errors may contain protocol details, never credentials
        logger.warning("GMP retrieval failed host=%s error_type=%s", host, type(error).__name__)
        raise GreenboneError(f"Échec GMP ({type(error).__name__}) ; vérifier certificat, version, identifiants et droits de lecture") from None
    return {"source_id": source_id, "source_name": host, "mode": "gmp", "gmp_version": version, "targets": targets}


def test_gmp(config: dict[str, Any], settings: Any, *, password: str | None = None) -> list[dict[str, str]]:
    """Perform bounded diagnostics; a TCP/TLS success is never reported as an auth success."""
    host = config["host"].strip().lower().rstrip(".")
    allowed = {value.strip().lower().rstrip(".") for value in settings.greenbone_allowed_hosts.split(",") if value.strip()}
    checks = [{"step": step, "status": "not_tested", "detail": ""} for step in ("DNS", "TCP", "TLS", "GMP", "Authentication", "Permissions", "Resources")]
    def mark(index: int, status: str, detail: str = "") -> None:
        checks[index] = {"step": checks[index]["step"], "status": status, "detail": detail[:240]}
    if not allowed or host not in allowed:
        mark(0, "failed", "Hôte absent de la liste exacte ORION_GREENBONE_ALLOWED_HOSTS")
        return checks
    try:
        answers = socket.getaddrinfo(host, config["port"], type=socket.SOCK_STREAM)
        ips = sorted({entry[4][0] for entry in answers})
        if any(ipaddress.ip_address(ip).is_loopback or ipaddress.ip_address(ip).is_link_local for ip in ips):
            raise OSError("adresse loopback/link-local refusée")
        mark(0, "ok", ", ".join(ips[:4]))
    except OSError as error:
        mark(0, "failed", f"Résolution impossible ({type(error).__name__})")
        return checks
    try:
        with socket.create_connection((host, config["port"]), timeout=config["timeout"]):
            mark(1, "ok", "Port GMP joignable")
    except OSError as error:
        mark(1, "failed", f"Connexion TCP impossible ({type(error).__name__})")
        return checks
    mark(2, "not_tested", "La négociation TLS sera testée par python-gvm")
    try:
        from gvm.connections import TLSConnection
        from gvm.protocols.gmp import GMP
        from gvm.transforms import EtreeCheckCommandTransform
        username = settings.greenbone_username or config.get("username", "")
        password = (settings.greenbone_password if password is None else password)
        if not username or not password:
            mark(2, "not_tested", "TLS non testé : identifiants GMP absents")
            mark(3, "not_tested", "Identifiants GMP absents")
            return checks
        connection = TLSConnection(hostname=host, port=config["port"], cafile=settings.greenbone_ca_file or None,
                                   certfile=settings.greenbone_client_cert_file or None, keyfile=settings.greenbone_client_key_file or None,
                                   timeout=config["timeout"])
        with GMP(connection=connection, transform=EtreeCheckCommandTransform()) as gmp:
            mark(2, "ok", "Certificat vérifié par python-gvm")
            try:
                version = _version(gmp.get_version())
            except Exception as error:  # noqa: BLE001
                mark(3, "failed", f"Protocole GMP incompatible ou invalide ({type(error).__name__})")
                return checks
            mark(3, "ok", version[:200])
            try:
                gmp.authenticate(username, password)
                mark(4, "ok", "Identifiants acceptés")
            except Exception as error:  # noqa: BLE001
                mark(4, "failed", f"Authentification refusée ({type(error).__name__})")
                return checks
            try:
                response = gmp.get_targets(filter_string="rows=1 first=1")
                root = ElementTree.fromstring(_xml_bytes(response))
                count = len(root.findall("target"))
            except Exception as error:  # noqa: BLE001
                mark(5, "failed", f"Commande de lecture refusée ou XML invalide ({type(error).__name__})")
                return checks
            mark(5, "ok", "Commandes de lecture acceptées")
            mark(6, "ok", f"Targets≥{count}")
    except ssl.SSLError as error:
        mark(2, "failed", f"Certificat/TLS invalide ({type(error).__name__})")
    except Exception as error:  # noqa: BLE001
        logger.warning("GMP diagnostic failed host=%s error_type=%s", host, type(error).__name__)
        mark(3, "failed", f"Échec GMP ({type(error).__name__})")
    return checks


def normalized_targets(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    """Normalize only Greenbone target addresses; ports and every other source field are ignored."""
    from orion_app.services.targets import TargetError, normalize_target

    records = []
    for source in snapshot.get("targets", []):
        for raw in source.get("hosts", []):
            try:
                value, kind = normalize_target(raw)
            except TargetError:
                continue
            records.append({"external_id": source.get("id", ""), "name": source.get("name", ""),
                            "comment": source.get("comment", ""), "source_host": raw,
                            "value": value, "kind": kind, "ports": "", "importable": True, "reason": ""})
            if len(records) > MAX_NORMALIZED_TARGETS:
                raise GreenboneError(f"Limite de {MAX_NORMALIZED_TARGETS} cibles normalisées atteinte")
    return records


def _target_link_key(item: dict[str, Any]) -> str:
    """Stable provenance key only; it is deliberately never used to decide target identity."""
    external_id = item.get("external_id") or "no-source-id"
    value = item["value"]
    key = f"{external_id}:{value}"
    return key if len(key) <= 128 else f"{external_id[:60]}:host:{hashlib.sha256(value.encode()).hexdigest()[:48]}"


def _snapshot_changes(db: Any, snapshot: dict[str, Any]) -> dict[str, Any]:
    """Compare source snapshots by normalized address and report absences without changing inventory."""
    from sqlalchemy import select

    source_id, import_id = snapshot.get("source_id"), snapshot.get("import_id")
    if not source_id or not import_id:
        return {"baseline_import_id": None, "changed": [], "absent": []}
    current = db.get(GreenboneImport, import_id)
    if current is None:
        return {"baseline_import_id": None, "changed": [], "absent": []}
    previous = db.execute(select(GreenboneImport).where(
        GreenboneImport.id != current.id, GreenboneImport.mode == current.mode,
        GreenboneImport.status == "done").order_by(GreenboneImport.created_at.desc()).limit(20)).scalars()
    baseline = next((row for row in previous if row.snapshot and row.snapshot.get("source_id") == source_id), None)
    if baseline is None:
        return {"baseline_import_id": None, "changed": [], "absent": []}

    def address_map(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
        result = {}
        for item in normalized_targets(data):
            result.setdefault(item["value"], item)
        return result

    before, after = address_map(baseline.snapshot), address_map(snapshot)
    absent = [{"type": "target", "id": value, "name": item.get("name") or value}
              for value, item in before.items() if value not in after]
    changed = [{"type": "target", "id": value, "name": item.get("name") or value}
               for value, item in before.items() if value in after and
               (item.get("name"), item.get("comment")) != (after[value].get("name"), after[value].get("comment"))]
    return {"baseline_import_id": str(baseline.id), "changed": changed, "absent": absent}


def preview(db: Any, snapshot: dict[str, Any]) -> dict[str, Any]:
    from sqlalchemy import select
    from orion_app.models import GreenboneObjectLink, Target

    # Collapse repeated source records by canonical address. The source UUID is traceability only.
    sources: dict[str, dict[str, Any]] = {}
    for item in normalized_targets(snapshot):
        sources.setdefault(item["value"], item)
    values = list(sources)
    existing: dict[str, list[Target]] = {}
    for offset in range(0, len(values), 400):
        rows = db.execute(select(Target).where(Target.value.in_(values[offset:offset + 400]))).scalars()
        for target in rows:
            existing.setdefault(target.value, []).append(target)
    links = {link.external_id for link in db.execute(select(GreenboneObjectLink).where(
        GreenboneObjectLink.source_id == snapshot["source_id"], GreenboneObjectLink.object_type == "target")).scalars()}
    items = []
    for value, source in sources.items():
        matches = existing.get(value, [])
        mapped = _target_link_key(source) in links
        if len(matches) > 1:
            action, reason = "ambiguous", "Plusieurs cibles historiques partagent cette adresse ; elles sont conservées sans modification."
        elif matches:
            action, reason = ("linked" if mapped else "existing"), ""
        else:
            action, reason = "new", ""
        items.append({**source, "existing_id": str(matches[0].id) if matches else None,
                      "existing_count": len(matches), "action": action, "reason": reason})
    summary = {key: sum(1 for item in items if item["action"] == key)
               for key in ("new", "existing", "linked", "ambiguous")}
    changes = _snapshot_changes(db, snapshot)
    warnings = ["Seules les adresses de cibles valides sont importées ; le périmètre des scans Orion reste inchangé.",
                "Une adresse absente de la récupération est signalée uniquement ; aucune cible ni association n’est supprimée."]
    invalid_count = sum(len(source.get("hosts", [])) for source in snapshot.get("targets", [])) - len(normalized_targets(snapshot))
    if invalid_count:
        warnings.append(f"{invalid_count} valeur(s) d’hôte invalide(s) ont été ignorées.")
    if summary["ambiguous"]:
        warnings.append(f"{summary['ambiguous']} adresse(s) correspondent à plusieurs cibles historiques ; aucune nouvelle cible ne sera créée.")
    if changes["baseline_import_id"] and changes["absent"]:
        warnings.append(f"{len(changes['absent'])} cible(s) de la récupération précédente sont absentes de la source actuelle ; l’inventaire Orion reste inchangé.")
    return {"summary": summary, "targets": items, "changes": changes, "warnings": warnings}


def apply(db: Any, snapshot: dict[str, Any], selected: list[int], actor: Any) -> dict[str, Any]:
    """Create only missing normalized addresses, preserving every pre-existing target and relation."""
    from sqlalchemy import select
    from sqlalchemy.exc import IntegrityError
    from orion_app.models import GreenboneObjectLink, ResourceTag, Tag, Target
    from orion_app.services import audit

    items = preview(db, snapshot)["targets"]
    if len(items) > MAX_NORMALIZED_TARGETS or len(selected) > MAX_NORMALIZED_TARGETS:
        raise GreenboneError("Limite de 5000 cibles par application")
    if any(index < 0 or index >= len(items) for index in selected):
        raise GreenboneError("Sélection invalide")
    tag = db.scalar(select(Tag).where(Tag.name == "Import OpenVAS"))
    counts = {"created": 0, "reused": 0, "ambiguous": 0}
    for index in sorted(set(selected)):
        item = items[index]
        matches = db.execute(select(Target).where(Target.value == item["value"]).order_by(Target.id)).scalars().all()
        if len(matches) > 1:
            counts["ambiguous"] += 1
            continue
        target = matches[0] if matches else None
        if target is None:
            candidate = Target(value=item["value"], kind=item["kind"], ports="", name=item["name"][:160],
                               description=item["comment"][:4000])
            try:
                with db.begin_nested():
                    db.add(candidate)
                    db.flush()
                target = candidate
                counts["created"] += 1
                if tag is None:
                    candidate_tag = Tag(name="Import OpenVAS")
                    try:
                        with db.begin_nested():
                            db.add(candidate_tag)
                            db.flush()
                        tag = candidate_tag
                    except IntegrityError:
                        tag = db.scalar(select(Tag).where(Tag.name == "Import OpenVAS"))
                        if tag is None:
                            raise
                db.add(ResourceTag(resource_type="target", resource_id=target.id, tag_id=tag.id))
            except IntegrityError:
                # A concurrent writer may have inserted this address after the preview.
                matches = db.execute(select(Target).where(Target.value == item["value"]).order_by(Target.id)).scalars().all()
                if len(matches) > 1:
                    counts["ambiguous"] += 1
                    continue
                if not matches:
                    raise
                target = matches[0]
                counts["reused"] += 1
        else:
            counts["reused"] += 1
        # Preserve Greenbone source identifiers for audit/provenance, never for deduplication.
        key = _target_link_key(item)
        link = db.scalar(select(GreenboneObjectLink).where(
            GreenboneObjectLink.source_id == snapshot["source_id"], GreenboneObjectLink.object_type == "target",
            GreenboneObjectLink.external_id == key))
        if link is None:
            try:
                with db.begin_nested():
                    db.add(GreenboneObjectLink(source_id=snapshot["source_id"], object_type="target", external_id=key,
                                               tls_id=str(target.id), mode=snapshot["mode"]))
                    db.flush()
            except IntegrityError:
                # Another idempotent import wrote this provenance link concurrently.
                pass
    audit.record(db, "greenbone.import.apply", actor=actor, resource_type="greenbone_import",
                 resource_id=str(snapshot.get("import_id", "")),
                 detail={"source": snapshot.get("source_name", ""), **counts, "selected": len(set(selected))})
    return counts


def process_next(db: Any, settings: Any) -> bool:
    """Worker handler for one queued GMP retrieval; no Greenbone write command is ever issued."""
    from datetime import UTC, datetime, timedelta
    from sqlalchemy import select

    now = datetime.now(UTC)
    for stale in db.execute(select(GreenboneImport).where(GreenboneImport.status.in_(("running", "applying")))).scalars():
        if stale.heartbeat_at and stale.heartbeat_at < now - timedelta(minutes=3):
            stale.status, stale.error, stale.finished_at = "failed", "worker lost", now
    row = db.execute(select(GreenboneImport).where(GreenboneImport.status == "queued", GreenboneImport.mode == "gmp")
                     .order_by(GreenboneImport.created_at).limit(1).with_for_update(skip_locked=True)).scalar_one_or_none()
    if row is None:
        db.commit()
        return False
    row.status, row.heartbeat_at = "running", now
    db.commit()
    row_id = row.id
    connection = dict(row.snapshot["connection"])
    def update_progress(info: dict[str, Any]) -> None:
        current = db.get(GreenboneImport, row_id)
        if current is not None and current.status == "running":
            current.progress = info
            current.heartbeat_at = datetime.now(UTC)
            db.commit()
    try:
        snapshot = retrieve_gmp(connection, settings, progress=update_progress,
                                password=connector_password(db, connection, settings))
        summary = {"targets": len(snapshot.get("targets", []))}
        current = db.get(GreenboneImport, row.id)
        current.snapshot = snapshot
        current.status, current.finished_at, current.error, current.progress = "done", datetime.now(UTC), "", {"phase": "complete", "objects": summary}
        current.result = {"objects": summary, "gmp_version": snapshot.get("gmp_version")}
        db.commit()
        return True
    except GreenboneError as error:
        current = db.get(GreenboneImport, row.id)
        current.status, current.finished_at, current.error, current.progress = "failed", datetime.now(UTC), str(error)[:500], None
        db.commit()
        logger.warning("GMP import failed job=%s error=%s", row.id, str(error)[:200])
        return True
    except Exception as error:  # noqa: BLE001
        db.rollback()
        current = db.get(GreenboneImport, row.id)
        current.status, current.finished_at, current.error, current.progress = "failed", datetime.now(UTC), f"Erreur interne ({type(error).__name__})", None
        db.commit()
        logger.exception("GMP import failed job=%s", row.id)
        return True


def process_apply_next(db: Any) -> bool:
    """Apply one administrator-confirmed selection transactionally in the worker, never in the HTTP request."""
    from datetime import UTC, datetime
    from sqlalchemy import select
    from orion_app.models import GreenboneImport, Role, User

    row = db.execute(select(GreenboneImport).where(GreenboneImport.status == "apply_queued")
                     .order_by(GreenboneImport.created_at).limit(1).with_for_update(skip_locked=True)).scalar_one_or_none()
    if row is None:
        return False
    request = dict((row.result or {}).get("apply_request") or {})
    row.status, row.heartbeat_at, row.progress = "applying", datetime.now(UTC), {"phase": "applying"}
    db.commit()
    try:
        actor = db.get(User, row.requested_by)
        if actor is None or not actor.active or actor.role != Role.ADMIN:
            raise GreenboneError("L’administrateur demandeur n’est plus actif ; import refusé")
        snapshot = dict(row.snapshot or {})
        snapshot["import_id"] = str(row.id)
        counts = apply(db, snapshot, request.get("selected", []), actor)
        current = db.get(GreenboneImport, row.id)
        current.status, current.finished_at, current.progress = "done", datetime.now(UTC), {"phase": "complete"}
        current.result = {"applied": counts}
        db.commit()
        return True
    except GreenboneError as error:
        db.rollback()
        current = db.get(GreenboneImport, row.id)
        current.status, current.finished_at, current.error, current.progress = "failed", datetime.now(UTC), str(error)[:500], None
        db.commit()
        return True
    except Exception as error:  # noqa: BLE001
        db.rollback()
        current = db.get(GreenboneImport, row.id)
        current.status, current.finished_at, current.error, current.progress = "failed", datetime.now(UTC), f"Erreur interne ({type(error).__name__})", None
        db.commit()
        logger.exception("Greenbone apply failed job=%s", row.id)
        return True
