"""Read-only Greenbone extraction and the shared normalized import model."""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import ssl
import socket
import xml.etree.ElementTree as ET
from typing import Any

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException

from tls_scan_app.models import GreenboneImport

logger = logging.getLogger("tls_scan_app.greenbone")
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
    if root.tag not in {"get_targets_response", "get_tasks_response", "get_port_lists_response", "get_scan_configs_response",
                        "get_schedules_response", "get_tags_response", "get_configs_response", "get_config_response"}:
        raise GreenboneError("Ce fichier n’est pas un export de configuration GMP reconnu (un rapport de scan n’est pas accepté)")
    status = root.get("status")
    if status is not None and status != "200":
        raise GreenboneError(f"Réponse GMP en erreur (statut {status})")
    return root


def _target(node: ET.Element) -> dict[str, Any]:
    hosts = [h.strip() for h in _text(node, "hosts").replace(",", " ").split() if h.strip()]
    exclude = [h.strip() for h in _text(node, "exclude_hosts").replace(",", " ").split() if h.strip()]
    port_list = node.find("port_list")
    return {"id": _id(node), "name": _text(node, "name"), "comment": _text(node, "comment"), "hosts": hosts,
            "exclusions": exclude, "port_list_id": port_list.get("id", "") if port_list is not None else "",
            "port_list_name": _text(port_list, "name") if port_list is not None else ""}


def _item(node: ET.Element, object_type: str) -> dict[str, Any]:
    item = {"id": _id(node), "name": _text(node, "name"), "comment": _text(node, "comment")}
    refs = {key: node.find(key) for key in ("target", "config", "scanner", "schedule", "port_list")}
    item["refs"] = {key: (ref.get("id", "") if ref is not None else "") for key, ref in refs.items()}
    if object_type == "port_lists":
        entries = []
        for port_range in node.findall("./port_ranges/port_range"):
            entries.append({"type": _text(port_range, "type", port_range.get("type", "tcp")).lower(),
                            "start": _text(port_range, "start"), "end": _text(port_range, "end")})
        item["ranges"] = entries
    if object_type == "schedules":
        item["timezone"] = _text(node, "timezone")
        item["first_time"] = _text(node, "first_time")
        item["period"] = _text(node, "period")
    return item


def normalize_xml(files: list[tuple[str, bytes]]) -> dict[str, Any]:
    if not files or len(files) > MAX_XML_FILES:
        raise GreenboneError(f"Fournir entre 1 et {MAX_XML_FILES} fichiers XML")
    total = sum(len(data) for _, data in files)
    if total > MAX_XML_BYTES:
        raise GreenboneError(f"Taille totale XML supérieure à {MAX_XML_BYTES // (1024 * 1024)} Mio")
    normalized: dict[str, list[dict[str, Any]]] = {k: [] for k in ("targets", "tasks", "port_lists", "scan_configs", "schedules", "tags")}
    for filename, data in files:
        root = _parse_document(data)
        kind = root.tag.removesuffix("_response")
        if kind == "get_configs":
            kind = "get_scan_configs"
        if kind == "get_config":
            kind = "get_scan_configs"
        key = {"get_targets": "targets", "get_tasks": "tasks", "get_port_lists": "port_lists", "get_scan_configs": "scan_configs",
               "get_schedules": "schedules", "get_tags": "tags"}.get(kind)
        if key is None:
            raise GreenboneError(f"Type XML non pris en charge : {filename}")
        for node in root:
            if node.tag not in ("target", "task", "port_list", "config", "schedule", "tag"):
                continue
            normalized[key].append(_target(node) if key == "targets" else _item(node, key))
            if sum(map(len, normalized.values())) > MAX_OBJECTS:
                raise GreenboneError(f"Trop d’objets XML (limite {MAX_OBJECTS})")
    source_id = "xml:" + hashlib.sha256(b"".join(data for _, data in files)).hexdigest()[:32]
    return {"source_id": source_id, "source_name": ", ".join(name[:100] for name, _ in files), "mode": "xml", **normalized}


def _xml_bytes(response: Any) -> bytes:
    return ET.tostring(response, encoding="utf-8")


def _paginate(method: Any, tag: str, object_type: str, *, maximum: int = MAX_OBJECTS) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for offset in range(0, maximum, PAGE_SIZE):
        options = {"filter_string": f"rows={PAGE_SIZE} first={offset + 1}"}
        if object_type == "port_lists":
            # GMP omits <port_ranges> unless details are explicitly requested.
            options["details"] = True
        response = method(**options)
        root = ElementTree.fromstring(_xml_bytes(response))
        page = root.findall(tag)
        rows.extend(_target(node) if object_type == "targets" else _item(node, object_type) for node in page)
        if len(page) < PAGE_SIZE:
            return rows
    raise GreenboneError(f"Limite de {maximum} objets atteinte ; récupération potentiellement partielle")


def retrieve_gmp(config: dict[str, Any], settings: Any, progress=lambda _: None) -> dict[str, Any]:
    host = config["host"].strip().lower().rstrip(".")
    allowed = {value.strip().lower().rstrip(".") for value in settings.greenbone_allowed_hosts.split(",") if value.strip()}
    if not allowed or host not in allowed:
        raise GreenboneError("Hôte refusé : configurez son nom exact dans TLS_SCAN_GREENBONE_ALLOWED_HOSTS")
    username = settings.greenbone_username or config.get("username", "")
    password = settings.greenbone_password
    if not username or not password:
        raise GreenboneError("Identifiants GMP absents (TLS_SCAN_GREENBONE_USERNAME et mot de passe/fichier secret)")
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
            targets = _paginate(gmp.get_targets, "target", "targets")
            progress({"phase": "tasks", "targets": len(targets)})
            tasks = _paginate(gmp.get_tasks, "task", "tasks")
            progress({"phase": "port_lists", "targets": len(targets), "tasks": len(tasks)})
            port_lists = _paginate(gmp.get_port_lists, "port_list", "port_lists")
            progress({"phase": "scan_configs", "port_lists": len(port_lists)})
            scan_configs = _paginate(gmp.get_scan_configs, "config", "scan_configs")
            progress({"phase": "schedules"})
            schedules = _paginate(gmp.get_schedules, "schedule", "schedules")
            progress({"phase": "tags"})
            tags = _paginate(gmp.get_tags, "tag", "tags")
    except Exception as error:  # errors may contain protocol details, never credentials
        logger.warning("GMP retrieval failed host=%s error_type=%s", host, type(error).__name__)
        raise GreenboneError(f"Échec GMP ({type(error).__name__}) ; vérifier certificat, version, identifiants et droits de lecture") from None
    return {"source_id": source_id, "source_name": host, "mode": "gmp", "gmp_version": version, "targets": targets,
            "tasks": tasks, "port_lists": port_lists, "scan_configs": scan_configs, "schedules": schedules, "tags": tags}


def test_gmp(config: dict[str, Any], settings: Any) -> list[dict[str, str]]:
    """Perform bounded diagnostics; a TCP/TLS success is never reported as an auth success."""
    host = config["host"].strip().lower().rstrip(".")
    allowed = {value.strip().lower().rstrip(".") for value in settings.greenbone_allowed_hosts.split(",") if value.strip()}
    checks = [{"step": step, "status": "not_tested", "detail": ""} for step in ("DNS", "TCP", "TLS", "GMP", "Authentication", "Permissions", "Resources")]
    def mark(index: int, status: str, detail: str = "") -> None:
        checks[index] = {"step": checks[index]["step"], "status": status, "detail": detail[:240]}
    if not allowed or host not in allowed:
        mark(0, "failed", "Hôte absent de la liste exacte TLS_SCAN_GREENBONE_ALLOWED_HOSTS")
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
        password = settings.greenbone_password
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
                counts = {}
                for label, method in (("targets", gmp.get_targets), ("tasks", gmp.get_tasks), ("port_lists", gmp.get_port_lists),
                                      ("scan_configs", gmp.get_scan_configs), ("schedules", gmp.get_schedules), ("tags", gmp.get_tags)):
                    response = method(filter_string="rows=1 first=1")
                    root = ElementTree.fromstring(_xml_bytes(response))
                    element = {"targets": "target", "tasks": "task", "port_lists": "port_list", "scan_configs": "config", "schedules": "schedule", "tags": "tag"}[label]
                    counts[label] = len(root.findall(element))
            except Exception as error:  # noqa: BLE001
                mark(5, "failed", f"Commande de lecture refusée ou XML invalide ({type(error).__name__})")
                return checks
            mark(5, "ok", "Commandes de lecture acceptées")
            mark(6, "ok", ", ".join(f"{key}≥{count}" for key, count in counts.items()))
    except ssl.SSLError as error:
        mark(2, "failed", f"Certificat/TLS invalide ({type(error).__name__})")
    except Exception as error:  # noqa: BLE001
        logger.warning("GMP diagnostic failed host=%s error_type=%s", host, type(error).__name__)
        mark(3, "failed", f"Échec GMP ({type(error).__name__})")
    return checks


def _target_port_map(snapshot: dict[str, Any]) -> dict[str, str]:
    output = {}
    for port_list in snapshot.get("port_lists", []):
        ranges: list[tuple[int, int]] = []
        for item in port_list.get("ranges", []):
            if item.get("type") != "tcp":
                continue
            try:
                start, end = int(item["start"]), int(item.get("end") or item["start"])
                if 1 <= start <= end <= 65535:
                    ranges.append((start, end))
            except (TypeError, ValueError, KeyError):
                continue
        merged: list[list[int]] = []
        for start, end in sorted(ranges):
            if merged and start <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([start, end])
        value = ",".join(str(start) if start == end else f"{start}-{end}" for start, end in merged)
        try:
            from tls_scan_app.services.targets import normalize_ports
            output[port_list["id"]] = normalize_ports(value) if len(value) <= 120 else ""
        except ValueError:
            output[port_list["id"]] = ""
    return output


def normalized_targets(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    from tls_scan_app.services.targets import TargetError, normalize_ports, normalize_target

    port_map = _target_port_map(snapshot)
    records = []
    for group in snapshot.get("targets", []):
        ports = normalize_ports(port_map.get(group.get("port_list_id", ""), ""))
        for raw in group.get("hosts", []):
            try:
                value, kind = normalize_target(raw)
            except TargetError:
                continue
            records.append({"external_id": group.get("id", ""), "name": group.get("name", ""), "comment": group.get("comment", ""),
                            "source_host": raw, "value": value, "kind": kind, "ports": ports,
                            "group_name": group.get("name", "OpenVAS"), "exclusions": group.get("exclusions", []),
                            "importable": bool(group.get("id") and group.get("port_list_id") and ports),
                            "reason": "" if group.get("id") and group.get("port_list_id") and ports else
                            "Identifiant OpenVAS manquant." if not group.get("id") else
                            "Aucune liste de ports TCP exploitable : import refusé pour ne pas élargir le périmètre TLS."})
            if len(records) > MAX_NORMALIZED_TARGETS:
                raise GreenboneError(f"Limite de {MAX_NORMALIZED_TARGETS} cibles normalisées atteinte")
    return records


def preview(db: Any, snapshot: dict[str, Any]) -> dict[str, Any]:
    from sqlalchemy import select, tuple_
    from tls_scan_app.models import GreenboneObjectLink, Policy, PolicyVersion, ScanProfile, ScanProfileVersion, Target

    sources = normalized_targets(snapshot)
    target_map = {}
    link_ids = set()
    identities = list(dict.fromkeys((item["value"], item["ports"]) for item in sources if item["importable"]))
    external_ids = list(dict.fromkeys(item["external_id"] + ":" + item["value"] for item in sources if item["importable"]))
    for offset in range(0, len(identities), 400):
        for target in db.execute(select(Target).where(tuple_(Target.value, Target.ports).in_(identities[offset:offset + 400]))).scalars():
            target_map[(target.value, target.ports)] = target
    for offset in range(0, len(external_ids), 400):
        link_ids.update(db.execute(select(GreenboneObjectLink.external_id).where(
            GreenboneObjectLink.source_id == snapshot["source_id"], GreenboneObjectLink.object_type == "target",
            GreenboneObjectLink.external_id.in_(external_ids[offset:offset + 400]))).scalars())
    items = []
    for source in sources:
        if not source["importable"]:
            items.append({**source, "existing_id": None, "action": "unimportable"})
            continue
        existing = target_map.get((source["value"], source["ports"]))
        is_linked = source["external_id"] + ":" + source["value"] in link_ids
        items.append({**source, "existing_id": str(existing.id) if existing else None,
                      "action": "linked" if is_linked else "existing" if existing else "new"})
    summary = {key: sum(1 for item in items if item["action"] == key) for key in ("new", "existing", "linked", "unimportable")}
    target_ids = {target.get("id") for target in snapshot.get("targets", [])}
    tasks = [{**task, "missing_target": not bool(task.get("refs", {}).get("target")) or task["refs"]["target"] not in target_ids}
             for task in snapshot.get("tasks", [])]
    published_profiles = set(db.execute(select(ScanProfileVersion.profile_id).where(ScanProfileVersion.status == "published").distinct()).scalars())
    published_policies = set(db.execute(select(PolicyVersion.policy_id).where(PolicyVersion.status == "published").distinct()).scalars())
    profiles = db.execute(select(ScanProfile).where(ScanProfile.archived.is_(False)).order_by(ScanProfile.name)).scalars()
    policies = db.execute(select(Policy).where(Policy.archived.is_(False)).order_by(Policy.name)).scalars()
    profile_options = [{"id": str(p.id), "name": p.name, "published": p.id in published_profiles} for p in profiles]
    policy_options = [{"id": str(p.id), "name": p.name, "published": p.id in published_policies} for p in policies]
    missing_exclusions = sum(bool(item.get("exclusions")) for item in normalized_targets(snapshot))
    warnings = ["Les NVT et credentials ne sont jamais importés.", "Les ports UDP sont ignorés.",
                "Les planifications Greenbone sont informatives et ne sont jamais activées automatiquement."]
    if missing_exclusions:
        warnings.append(f"{missing_exclusions} cible(s) ont des exclusions Greenbone non transférées automatiquement.")
    invalid_hosts = [{"target": group.get("name", ""), "host": raw} for group in snapshot.get("targets", []) for raw in group.get("hosts", [])
                     if _invalid_host(raw)]
    if invalid_hosts:
        warnings.append(f"{len(invalid_hosts)} hôte(s) ne sont pas des IP, FQDN ou CIDR TLS Scan valides.")
    no_tcp = sum(item["action"] == "unimportable" for item in items)
    if no_tcp:
        warnings.append(f"{no_tcp} cible(s) sans ports TCP transférables sont exclues pour éviter d’élargir le périmètre.")
    if any(task["missing_target"] for task in tasks):
        warnings.append(f"{sum(task['missing_target'] for task in tasks)} Task(s) référencent une Target absente du jeu importé.")
    return {"summary": summary, "targets": items, "groups": len({i["group_name"] for i in items}), "tasks": tasks,
            "port_lists": snapshot.get("port_lists", []), "scan_configs": snapshot.get("scan_configs", []),
            "schedules": snapshot.get("schedules", []), "tags": snapshot.get("tags", []),
            "profiles": profile_options, "policies": policy_options, "warnings": warnings, "invalid_hosts": invalid_hosts}


def _invalid_host(value: str) -> bool:
    from tls_scan_app.services.targets import TargetError, normalize_target
    try:
        normalize_target(value)
        return False
    except TargetError:
        return True


def apply(db: Any, snapshot: dict[str, Any], selected: list[int], actor: Any, *, import_groups: bool, add_tag: bool,
          definitions: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    from sqlalchemy import select
    from tls_scan_app.models import GreenboneObjectLink, ResourceTag, Tag, Target, TargetGroup, TargetGroupMember
    from tls_scan_app.services import audit

    items = normalized_targets(snapshot)
    if len(items) > 5000 or len(selected) > 5000:
        raise GreenboneError("Limite de 5000 cibles par application")
    if any(index < 0 or index >= len(items) for index in selected):
        raise GreenboneError("Sélection invalide")
    if any(not items[index]["importable"] for index in selected):
        raise GreenboneError("Une ou plusieurs cibles sélectionnées n’ont pas de ports TCP transférables")
    tag = db.scalar(select(Tag).where(Tag.name == "Import OpenVAS"))
    if add_tag and tag is None:
        tag = Tag(name="Import OpenVAS")
        db.add(tag)
        db.flush()
    groups: dict[str, TargetGroup] = {}
    counts = {"created": 0, "reused": 0, "groups_created": 0, "groups_reused": 0, "definitions_created": 0, "definitions_reused": 0}
    for index in sorted(set(selected)):
        item = items[index]
        existing = db.scalar(select(Target).where(Target.value == item["value"], Target.ports == item["ports"]))
        target = existing
        if target is None:
            target = Target(value=item["value"], kind=item["kind"], ports=item["ports"], name=item["name"][:160], description=item["comment"][:4000])
            db.add(target)
            db.flush()
            counts["created"] += 1
        else:
            counts["reused"] += 1
        if import_groups:
            name = item["group_name"][:120] or "OpenVAS"
            group = groups.get(name) or db.scalar(select(TargetGroup).where(TargetGroup.name == name))
            if group is None:
                group = TargetGroup(name=name)
                db.add(group)
                db.flush()
                counts["groups_created"] += 1
            elif name not in groups:
                counts["groups_reused"] += 1
            groups[name] = group
            membership = db.get(TargetGroupMember, (group.id, target.id))
            if membership is None:
                db.add(TargetGroupMember(group_id=group.id, target_id=target.id))
        if tag and (not existing):
            db.add(ResourceTag(resource_type="target", resource_id=target.id, tag_id=tag.id))
        key = item["external_id"] + ":" + item["value"]
        link = db.scalar(select(GreenboneObjectLink).where(GreenboneObjectLink.source_id == snapshot["source_id"],
                           GreenboneObjectLink.object_type == "target", GreenboneObjectLink.external_id == key))
        if link is None:
            db.add(GreenboneObjectLink(source_id=snapshot["source_id"], object_type="target", external_id=key, tls_id=str(target.id), mode=snapshot["mode"]))
    apply_definitions(db, snapshot, selected, actor, definitions or [], counts)
    audit.record(db, "greenbone.import.apply", actor=actor, resource_type="greenbone_import", resource_id=str(snapshot.get("import_id", "")),
                 detail={"source": snapshot["source_name"], **counts, "selected": len(set(selected))})
    return counts


def validate_definition_choices(db: Any, snapshot: dict[str, Any], choices: list[dict[str, Any]],
                               selected_targets: list[int] | None = None) -> list[dict[str, Any]]:
    from sqlalchemy import select
    from tls_scan_app.models import GreenboneObjectLink, Policy, PolicyVersion, ScanProfile, ScanProfileVersion

    tasks = {task.get("id"): task for task in snapshot.get("tasks", [])}
    normalized = normalized_targets(snapshot)
    selected_sources = {normalized[index]["external_id"] for index in set(selected_targets or [])
                        if 0 <= index < len(normalized)}
    seen_tasks: set[str] = set()
    validated = []
    for choice in choices:
        task = tasks.get(choice["task_id"])
        if task is None or not task.get("id"):
            raise GreenboneError("Task Greenbone inconnue ou sans identifiant stable")
        target_ref = task.get("refs", {}).get("target")
        if not target_ref or not any(t.get("id") == target_ref for t in snapshot.get("targets", [])):
            raise GreenboneError(f"Target Greenbone référencée mais non fournie pour la Task {task.get('name', '')}")
        if task["id"] in seen_tasks:
            raise GreenboneError("Une Task ne peut être sélectionnée qu’une fois")
        seen_tasks.add(task["id"])
        profile = db.get(ScanProfile, choice["profile_id"])
        if profile is None or profile.archived or not db.scalar(select(ScanProfileVersion.id).where(
            ScanProfileVersion.profile_id == profile.id, ScanProfileVersion.status == "published").limit(1)):
            raise GreenboneError("Le profil TLS Scan choisi doit exister et avoir une version publiée")
        policy_ids = list(dict.fromkeys(choice["policy_ids"]))
        if not policy_ids:
            raise GreenboneError("Une ou plusieurs politiques TLS Scan publiées sont requises pour chaque définition")
        policies = []
        for policy_id in policy_ids:
            policy = db.get(Policy, policy_id)
            if policy is None or policy.archived or not db.scalar(select(PolicyVersion.id).where(
                PolicyVersion.policy_id == policy.id, PolicyVersion.status == "published").limit(1)):
                raise GreenboneError("Chaque politique choisie doit avoir une version publiée")
            policies.append(policy)
        link = db.scalar(select(GreenboneObjectLink).where(GreenboneObjectLink.source_id == snapshot["source_id"],
                          GreenboneObjectLink.object_type == "task", GreenboneObjectLink.external_id == task["id"]))
        if selected_targets is not None and not link and target_ref not in selected_sources:
            raise GreenboneError(f"Sélectionnez au moins une cible de la Target Greenbone liée à la Task {task.get('name', '')}")
        validated.append({"task": task, "profile": profile, "policies": policies, "existing_id": link.tls_id if link else None})
    return validated


def apply_definitions(db: Any, snapshot: dict[str, Any], selected_targets: list[int], actor: Any,
                      choices: list[dict[str, Any]], counts: dict[str, int]) -> None:
    from sqlalchemy import select
    from tls_scan_app.models import DefinitionPolicy, DefinitionTarget, GreenboneObjectLink, ScanDefinition, Target

    targets = normalized_targets(snapshot)
    selected_by_source: dict[str, dict[str, Any]] = {}
    for index in sorted(set(selected_targets)):
        if 0 <= index < len(targets):
            selected_by_source.setdefault(targets[index]["external_id"], {})[targets[index]["value"]] = targets[index]
    for choice in validate_definition_choices(db, snapshot, choices, selected_targets):
        task = choice["task"]
        if choice["existing_id"]:
            counts["definitions_reused"] += 1
            continue
        selected_values = selected_by_source.get(task["refs"]["target"], {})
        if not selected_values:
            raise GreenboneError(f"Aucune cible sélectionnée pour la Task {task.get('name', '')}")
        target_ids = []
        for item in selected_values.values():
            target = db.scalar(select(Target).where(Target.value == item["value"], Target.ports == item["ports"]))
            if target is not None:
                target_ids.append(target.id)
        if not target_ids:
            raise GreenboneError(f"Aucune cible TLS Scan correspondante pour la Task {task.get('name', '')}")
        definition = ScanDefinition(name=(task.get("name") or "OpenVAS task")[:160], description=(task.get("comment") or "")[:4000],
                                    owner_id=actor.id, updated_by=actor.id, profile_id=choice["profile"].id)
        db.add(definition)
        db.flush()
        db.add_all([DefinitionTarget(definition_id=definition.id, target_id=target_id) for target_id in sorted(set(target_ids), key=str)])
        db.add_all([DefinitionPolicy(definition_id=definition.id, policy_id=policy.id) for policy in choice["policies"]])
        db.add(GreenboneObjectLink(source_id=snapshot["source_id"], object_type="task", external_id=task["id"],
                                   tls_id=str(definition.id), mode=snapshot["mode"]))
        counts["definitions_created"] += 1


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
        snapshot = retrieve_gmp(connection, settings, progress=update_progress)
        summary = {key: len(snapshot[key]) for key in ("targets", "tasks", "port_lists", "scan_configs", "schedules", "tags")}
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
    from tls_scan_app.models import GreenboneImport, Role, User

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
        counts = apply(db, snapshot, request.get("selected", []), actor,
                       import_groups=bool(request.get("import_groups", True)), add_tag=bool(request.get("add_tag", True)),
                       definitions=request.get("definitions", []))
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
