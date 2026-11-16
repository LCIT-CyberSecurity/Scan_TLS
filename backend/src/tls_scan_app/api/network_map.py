"""Network exposure map: real TLS results plus explicitly declared topology."""
from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import and_, delete, func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from tls_scan_app.api.common import get_or_404
from tls_scan_app.deps import get_db, require_role
from tls_scan_app.models import (
    InformationSystem, NetworkDevice, NetworkLink, NetworkZone, NetworkZoneSystem, NetworkZoneTarget,
    ResourceSI, ResourceTag, Role, RunEndpoint, RunFinding, ScanRun, Tag, Target, TargetGroup, TargetGroupMember, User,
)
from tls_scan_app.services import audit

router = APIRouter(prefix="/api/map", tags=["network-map"])
reader = require_role(Role.USER)
operator = require_role(Role.OPERATOR)
FINISHED = ("completed", "partial")
PROVENANCE = Literal["DECLARED", "OBSERVED", "INFERRED"]
DEVICE_TYPES = Literal["router", "firewall", "gateway", "switch", "load_balancer", "reverse_proxy", "server", "subnet", "generic"]


def _uuid_values(values: list[uuid.UUID]) -> list[uuid.UUID]:
    return list(dict.fromkeys(values))


def _validate_ip(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as error:
        raise HTTPException(422, "Invalid IP address") from error


def _validate_cidr(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    try:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    except ValueError as error:
        raise HTTPException(422, "Invalid CIDR network") from error


def _validate_confidence(value: float | None) -> float | None:
    if value is not None and not 0 <= value <= 1:
        raise HTTPException(422, "Confidence must be between 0 and 1")
    return value


def _validate_zone_cycle(db: DbSession, zone_id: uuid.UUID | None, parent_id: uuid.UUID | None) -> None:
    if parent_id is None:
        return
    get_or_404(db, NetworkZone, parent_id, "Parent zone")
    if parent_id == zone_id:
        raise HTTPException(422, "A zone cannot be its own parent")
    current = parent_id
    seen: set[uuid.UUID] = set()
    while current:
        if current in seen or current == zone_id:
            raise HTTPException(422, "Zone hierarchy must not contain a cycle")
        seen.add(current)
        current = db.scalar(select(NetworkZone.parent_zone_id).where(NetworkZone.id == current))


def _validate_associations(db: DbSession, si_ids: list[uuid.UUID], target_ids: list[uuid.UUID]) -> None:
    if si_ids and len(db.execute(select(InformationSystem.id).where(InformationSystem.id.in_(set(si_ids)))).scalars().all()) != len(set(si_ids)):
        raise HTTPException(422, "Unknown information system")
    if target_ids and len(db.execute(select(Target.id).where(Target.id.in_(set(target_ids)))).scalars().all()) != len(set(target_ids)):
        raise HTTPException(422, "Unknown target")


class ZoneBody(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=4000)
    zone_type: str = Field(default="custom", min_length=1, max_length=40)
    parent_zone_id: uuid.UUID | None = None
    cidr: str | None = Field(default=None, max_length=64)
    si_ids: list[uuid.UUID] = Field(default_factory=list, max_length=200)
    target_ids: list[uuid.UUID] = Field(default_factory=list, max_length=2000)
    primary_target_ids: list[uuid.UUID] = Field(default_factory=list, max_length=2000)

    @model_validator(mode="after")
    def non_blank_name(self) -> "ZoneBody":
        if not self.name.strip() or not self.zone_type.strip():
            raise ValueError("Zone name and type must not be blank")
        return self


class DeviceBody(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    device_type: DEVICE_TYPES = "generic"
    zone_id: uuid.UUID | None = None
    ip_address: str | None = Field(default=None, max_length=64)
    target_id: uuid.UUID | None = None
    provenance: PROVENANCE = "DECLARED"
    source: str = Field(default="", max_length=255)
    observed_at: datetime | None = None
    confidence: float | None = None
    metadata: dict[str, str | int | float | bool | None] = Field(default_factory=dict, alias="metadata")

    @model_validator(mode="after")
    def provenance_has_evidence(self) -> "DeviceBody":
        if not self.name.strip():
            raise ValueError("Device name must not be blank")
        if self.provenance in ("OBSERVED", "INFERRED") and not self.source.strip():
            raise ValueError("Observed or inferred devices require an evidence source")
        if self.provenance == "OBSERVED" and self.observed_at is None:
            raise ValueError("Observed devices require an observation date")
        if self.provenance == "INFERRED" and self.confidence is None:
            raise ValueError("Inferred devices require a confidence value")
        return self


class LinkBody(BaseModel):
    source_device_id: uuid.UUID
    target_device_id: uuid.UUID
    link_type: str = Field(default="network", min_length=1, max_length=40)
    provenance: PROVENANCE = "DECLARED"
    source: str = Field(default="", max_length=255)
    observed_at: datetime | None = None
    confidence: float | None = None
    description: str = Field(default="", max_length=4000)

    @model_validator(mode="after")
    def distinct_endpoints(self) -> "LinkBody":
        if not self.link_type.strip():
            raise ValueError("Link type must not be blank")
        if self.source_device_id == self.target_device_id:
            raise ValueError("A link must connect two different devices")
        if self.provenance in ("OBSERVED", "INFERRED") and not self.source.strip():
            raise ValueError("Observed or inferred links require an evidence source")
        if self.provenance == "OBSERVED" and self.observed_at is None:
            raise ValueError("Observed links require an observation date")
        if self.provenance == "INFERRED" and self.confidence is None:
            raise ValueError("Inferred links require a confidence value")
        return self


class ExposureOut(BaseModel):
    targets: int
    scanned_targets: int
    unscanned_targets: int
    severity: dict[str, int]


class SummarySystemOut(BaseModel):
    id: str
    name: str
    description: str
    children: list[dict[str, str]]
    exposure: ExposureOut


class SummaryOut(BaseModel):
    systems: list[SummarySystemOut]
    totals: dict[str, int]


class GraphNodeOut(BaseModel):
    id: str
    kind: Literal["si", "zone", "group", "host", "device", "unassigned"]
    name: str
    si_id: str | None = None
    zone_id: str | None = None
    target_id: str | None = None
    group_id: str | None = None
    value: str | None = None
    ports: str | None = None
    zone_type: str | None = None
    cidr: str | None = None
    count: int | None = None
    child_count: int | None = None
    device_type: str | None = None
    ip_address: str | None = None
    provenance: str | None = None
    exposure: dict | None = None


class GraphOut(BaseModel):
    scope: dict
    mode: Literal["si", "network"]
    nodes: list[GraphNodeOut]
    links: list[dict]
    truncated: bool
    next_offset: int | None = None
    totals: dict[str, int] | None = None


class ZoneOut(BaseModel):
    id: str
    name: str
    description: str
    zone_type: str
    parent_zone_id: str | None = None
    cidr: str | None = None
    si_ids: list[str]
    target_ids: list[str]
    primary_target_ids: list[str]


class DeviceOut(BaseModel):
    id: str
    name: str
    device_type: str
    zone_id: str | None = None
    ip_address: str | None = None
    target_id: str | None = None
    provenance: str
    source: str
    observed_at: datetime | None = None
    confidence: float | None = None
    metadata: dict


class LinkOut(BaseModel):
    id: str
    source_device_id: str
    target_device_id: str
    link_type: str
    provenance: str
    source: str
    observed_at: datetime | None = None
    confidence: float | None = None
    description: str


class SearchOut(BaseModel):
    kind: Literal["host", "si", "zone", "device"]
    id: str
    name: str
    value: str | None = None
    parent_zone_id: str | None = None
    zone_id: str | None = None
    si_ids: list[str] = []
    zone_ids: list[str] = []


class HostDetailOut(BaseModel):
    target: dict
    scan: dict | None
    findings: list[dict]


def _zone_out(db: DbSession, zone: NetworkZone) -> dict:
    return {
        "id": str(zone.id), "name": zone.name, "description": zone.description, "zone_type": zone.zone_type,
        "parent_zone_id": str(zone.parent_zone_id) if zone.parent_zone_id else None, "cidr": zone.cidr,
        "si_ids": [str(x) for x in db.execute(select(NetworkZoneSystem.si_id).where(NetworkZoneSystem.zone_id == zone.id)).scalars()],
        "target_ids": [str(x) for x in db.execute(select(NetworkZoneTarget.target_id).where(NetworkZoneTarget.zone_id == zone.id)).scalars()],
        "primary_target_ids": [str(x) for x in db.execute(select(NetworkZoneTarget.target_id).where(NetworkZoneTarget.zone_id == zone.id, NetworkZoneTarget.primary_placement.is_(True))).scalars()],
    }


def _device_out(item: NetworkDevice) -> dict:
    return {
        "id": str(item.id), "name": item.name, "device_type": item.device_type,
        "zone_id": str(item.zone_id) if item.zone_id else None, "ip_address": item.ip_address,
        "target_id": str(item.target_id) if item.target_id else None, "provenance": item.provenance,
        "source": item.source, "observed_at": item.observed_at, "confidence": item.confidence,
        "metadata": item.metadata_json or {},
    }


def _link_out(item: NetworkLink) -> dict:
    return {
        "id": str(item.id), "source_device_id": str(item.source_device_id), "target_device_id": str(item.target_device_id),
        "link_type": item.link_type, "provenance": item.provenance, "source": item.source,
        "observed_at": item.observed_at, "confidence": item.confidence, "description": item.description,
    }


def _target_latest(db: DbSession, target_values: set[str]) -> dict[str, dict]:
    """Return the most recent persisted TLS result whose run actually included the target value."""
    latest: dict[str, tuple[datetime, ScanRun]] = {}
    scanned_ports: dict[str, set[str]] = {}
    for run in db.execute(select(ScanRun).where(ScanRun.status.in_(FINISHED), ScanRun.finished_at.is_not(None)).order_by(ScanRun.finished_at.desc())).scalars():
        for pass_ in (run.config_snapshot or {}).get("passes", []):
            for value in pass_.get("targets", []):
                if value not in target_values:
                    continue
                if value not in latest:
                    latest[value] = (run.finished_at, run)
                if latest[value][1].id == run.id:
                    scanned_ports.setdefault(value, set()).add(str(pass_.get("ports", "")))
    run_ids = {run.id for _, run in latest.values()}
    endpoints_by_run: dict[uuid.UUID, list[RunEndpoint]] = {}
    if run_ids:
        for endpoint in db.execute(select(RunEndpoint).where(RunEndpoint.run_id.in_(run_ids))).scalars():
            endpoints_by_run.setdefault(endpoint.run_id, []).append(endpoint)
    out: dict[str, dict] = {}
    for value, (finished_at, run) in latest.items():
        result = out.setdefault(value, {"run_id": str(run.id), "status": run.status, "finished_at": finished_at,
                                        "endpoints": [], "severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                                        "compliant": 0, "non_compliant": 0, "unevaluated": 0,
                                        "scanned_ports": sorted(scanned_ports.get(value, set()))})
        for endpoint in endpoints_by_run.get(run.id, []):
            # Only associate an endpoint with its exact scanned name/address. A CIDR is safe to match because the run
            # itself explicitly scanned that network; DNS aliases and shared IPs are otherwise kept separate.
            matches = endpoint.hostname.casefold() == value.casefold()
            if not matches:
                try:
                    target_ip = ipaddress.ip_address(value)
                    matches = bool(endpoint.ip_address) and ipaddress.ip_address(endpoint.ip_address) == target_ip
                except ValueError:
                    try:
                        network = ipaddress.ip_network(value, strict=False)
                        matches = bool(endpoint.ip_address) and ipaddress.ip_address(endpoint.ip_address) in network
                    except ValueError:
                        matches = False
            if not matches:
                continue
            key = (endpoint.hostname or "", endpoint.ip_address, endpoint.port)
            if not any((x["hostname"] or "", x["ip_address"] or "", str(x["port"] or "")) == key for x in result["endpoints"]):
                result["endpoints"].append({"endpoint_id": endpoint.endpoint_id, "hostname": endpoint.hostname or None,
                                          "ip_address": endpoint.ip_address or None, "port": int(endpoint.port) if endpoint.port.isdigit() else None,
                                          "grade": endpoint.grade or None, "compliance_status": endpoint.compliance_status or None,
                                          "highest_severity": endpoint.highest_severity or None,
                                          "tls_versions": endpoint.supported_tls_versions or [], "cipher_suites": endpoint.cipher_suites or [],
                                          "certificate": endpoint.certificate or None, "errors": endpoint.errors or [],
                                          "untested_checks": endpoint.untested_checks or [], "tls_checks": endpoint.tls_checks or []})
                severity = endpoint.highest_severity
                if severity in result["severity"]:
                    result["severity"][severity] += 1
                if endpoint.compliance_status == "compliant":
                    result["compliant"] += 1
                elif endpoint.compliance_status == "non_compliant":
                    result["non_compliant"] += 1
                else:
                    result["unevaluated"] += 1
    return out


def _target_result(target: Target, latest: dict[str, dict]) -> dict | None:
    result = latest.get(target.value)
    if result is None:
        return None
    requested_ports = (target.ports or "").strip()
    if requested_ports and requested_ports not in {"fast", "all"} and requested_ports not in result.get("scanned_ports", []):
        return None
    filtered = {**result, "endpoints": [], "severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "compliant": 0, "non_compliant": 0, "unevaluated": 0}
    for endpoint in result["endpoints"]:
        port = endpoint.get("port")
        if requested_ports not in ("", "fast", "all") and port is not None:
            matches = False
            for part in requested_ports.split(","):
                bounds = part.split("-", 1)
                if len(bounds) == 1 and port == int(bounds[0]) or len(bounds) == 2 and int(bounds[0]) <= port <= int(bounds[1]):
                    matches = True
                    break
            if not matches:
                continue
        filtered["endpoints"].append(endpoint)
        severity = endpoint.get("highest_severity")
        if severity in filtered["severity"]:
            filtered["severity"][severity] += 1
        if endpoint.get("compliance_status") == "compliant":
            filtered["compliant"] += 1
        elif endpoint.get("compliance_status") == "non_compliant":
            filtered["non_compliant"] += 1
        else:
            filtered["unevaluated"] += 1
    return filtered


def _exposure(items: list[Target], latest: dict[str, dict]) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    scanned = 0
    targets = {item.id: item for item in items}
    for target in targets.values():
        result = _target_result(target, latest)
        if not result:
            continue
        scanned += 1
        for key, count in result["severity"].items():
            counts[key] += count
    return {"targets": len(targets), "scanned_targets": scanned, "unscanned_targets": len(targets) - scanned, "severity": counts}


def _targets_for_si(db: DbSession, si_ids: set[uuid.UUID]) -> list[Target]:
    if not si_ids:
        return []
    ids = set(db.execute(select(ResourceSI.resource_id).where(ResourceSI.resource_type == "target", ResourceSI.si_id.in_(si_ids))).scalars())
    group_ids = set(db.execute(select(ResourceSI.resource_id).where(ResourceSI.resource_type == "group", ResourceSI.si_id.in_(si_ids))).scalars())
    if group_ids:
        ids.update(db.execute(select(TargetGroupMember.target_id).where(TargetGroupMember.group_id.in_(group_ids))).scalars())
    ids.update(db.execute(select(NetworkZoneTarget.target_id).join(NetworkZoneSystem, NetworkZoneSystem.zone_id == NetworkZoneTarget.zone_id)
                          .where(NetworkZoneSystem.si_id.in_(si_ids))).scalars())
    return db.execute(select(Target).where(Target.id.in_(ids)).order_by(Target.value)).scalars().all() if ids else []


def _zone_exposures(db: DbSession, zone_ids: list[uuid.UUID], latest: dict[str, dict], allowed_targets: set[uuid.UUID] | None = None) -> dict[uuid.UUID, dict]:
    """Aggregate explicit target assignments through each nested zone, without deriving links from CIDRs."""
    if not zone_ids:
        return {}
    zones = db.execute(select(NetworkZone.id, NetworkZone.parent_zone_id)).all()
    children: dict[uuid.UUID | None, list[uuid.UUID]] = {}
    for zone_id, parent_id in zones:
        children.setdefault(parent_id, []).append(zone_id)
    descendants_by_root: dict[uuid.UUID, set[uuid.UUID]] = {}
    for root_id in zone_ids:
        descendants: set[uuid.UUID] = set()
        pending = [root_id]
        while pending:
            current = pending.pop()
            if current in descendants:
                continue
            descendants.add(current)
            pending.extend(children.get(current, []))
        descendants_by_root[root_id] = descendants
    zone_scope = set().union(*descendants_by_root.values()) if descendants_by_root else set()
    assignments_stmt = select(NetworkZoneTarget.zone_id, NetworkZoneTarget.target_id).where(NetworkZoneTarget.zone_id.in_(zone_scope))
    if allowed_targets is not None:
        if not allowed_targets:
            return {root_id: _exposure([], latest) for root_id in zone_ids}
        assignments_stmt = assignments_stmt.where(NetworkZoneTarget.target_id.in_(allowed_targets))
    targets_by_zone: dict[uuid.UUID, set[uuid.UUID]] = {}
    for assigned_zone, target_id in db.execute(assignments_stmt):
        targets_by_zone.setdefault(assigned_zone, set()).add(target_id)
    assigned_target_ids = set().union(*targets_by_zone.values()) if targets_by_zone else set()
    target_records = {target.id: target for target in db.execute(select(Target).where(Target.id.in_(assigned_target_ids))).scalars()} if assigned_target_ids else {}
    # A child zone can contain targets not assigned to its parent. Include those explicit
    # assignments before calculating exposure, so each visible child gets a truthful summary.
    missing_values = {target.value for target in target_records.values()} - set(latest)
    if missing_values:
        latest.update(_target_latest(db, missing_values))
    result: dict[uuid.UUID, dict] = {}
    for root_id, descendants in descendants_by_root.items():
        target_ids = {target_id for zone in descendants for target_id in targets_by_zone.get(zone, set())}
        items = [target_records[target_id] for target_id in target_ids if target_id in target_records]
        result[root_id] = _exposure(items, latest)
    return result


@router.get("/summary", response_model=SummaryOut)
def summary(db: DbSession = Depends(get_db), _: User = Depends(reader)) -> dict:
    systems = db.execute(select(InformationSystem).where(InformationSystem.parent_id.is_(None)).order_by(InformationSystem.name)).scalars().all()
    children = db.execute(select(InformationSystem).where(InformationSystem.parent_id.is_not(None)).order_by(InformationSystem.name)).scalars().all()
    children_by_parent: dict[uuid.UUID, list[InformationSystem]] = {}
    for child in children:
        children_by_parent.setdefault(child.parent_id, []).append(child)
    output = []
    targets_by_system: dict[uuid.UUID, list[Target]] = {}
    all_targets: dict[uuid.UUID, Target] = {}
    for si in systems:
        member_ids = {si.id, *(child.id for child in children_by_parent.get(si.id, []))}
        targets = _targets_for_si(db, member_ids)
        targets_by_system[si.id] = targets
        all_targets.update({target.id: target for target in targets})
    # The global map also represents assets that have not been classified into an SI.
    # Keep totals unique across SI, group and zone assignments.
    inventory = db.execute(select(Target)).scalars().all()
    all_targets.update({target.id: target for target in inventory})
    latest = _target_latest(db, {t.value for t in all_targets.values()})
    for si in systems:
        targets = targets_by_system[si.id]
        output.append({"id": str(si.id), "name": si.name, "description": si.description,
                       "children": [{"id": str(c.id), "name": c.name} for c in children_by_parent.get(si.id, [])],
                       "exposure": _exposure(targets, latest)})
    return {"systems": output, "totals": {"systems": len(systems), "targets": len(all_targets),
                                           "scanned_targets": _exposure(list(all_targets.values()), latest)["scanned_targets"]}}


@router.get("/graph", response_model=GraphOut)
def graph(
    si_id: uuid.UUID | None = None, zone_id: uuid.UUID | None = None, group_id: uuid.UUID | None = None, focus_target_id: uuid.UUID | None = None,
    mode: Literal["si", "network"] = "si", limit: int = Query(default=500, ge=1, le=2000),
    offset: int = Query(default=0, ge=0), expand_unassigned: bool = False,
    db: DbSession = Depends(get_db), _: User = Depends(reader),
) -> dict:
    """Return one exploration level at a time; host-level TLS data is loaded only on zone entry."""
    if group_id:
        group = get_or_404(db, TargetGroup, group_id, "Target group")
        targets = db.execute(select(Target).join(TargetGroupMember, TargetGroupMember.target_id == Target.id)
                             .where(TargetGroupMember.group_id == group.id).order_by(Target.value).offset(offset).limit(limit)).scalars().all()
        total = db.scalar(select(func.count()).select_from(TargetGroupMember).where(TargetGroupMember.group_id == group.id)) or 0
        latest = _target_latest(db, {item.value for item in targets})
        nodes = [{"id": f"target:{item.id}", "kind": "host", "name": item.name or item.value, "value": item.value,
                  "target_id": str(item.id), "ports": item.ports, "exposure": _target_result(item, latest)} for item in targets]
        return {"scope": {"group": {"id": str(group.id), "name": group.name}}, "mode": mode, "nodes": nodes, "links": [],
                "truncated": offset + len(targets) < total, "next_offset": offset + len(targets) if offset + len(targets) < total else None}

    if zone_id:
        zone = get_or_404(db, NetworkZone, zone_id, "Zone")
        children = db.execute(select(NetworkZone).where(NetworkZone.parent_zone_id == zone.id).order_by(NetworkZone.name)).scalars().all()
        target_ids = set(db.execute(select(NetworkZoneTarget.target_id).where(NetworkZoneTarget.zone_id == zone.id)).scalars())
        targets = db.execute(select(Target).where(Target.id.in_(target_ids)).order_by(Target.value).offset(offset).limit(limit)).scalars().all() if target_ids else []
        devices = db.execute(select(NetworkDevice).where(NetworkDevice.zone_id == zone.id).order_by(NetworkDevice.name)).scalars().all()
        device_ids = [item.id for item in devices]
        links = db.execute(select(NetworkLink).where(or_(NetworkLink.source_device_id.in_(device_ids), NetworkLink.target_device_id.in_(device_ids)))).scalars().all() if device_ids else []
        latest = _target_latest(db, {t.value for t in targets})
        child_exposure = _zone_exposures(db, [child.id for child in children], latest)
        nodes = [{"id": f"zone:{child.id}", "kind": "zone", "name": child.name, "zone_id": str(child.id), "zone_type": child.zone_type,
                  "cidr": child.cidr, "exposure": child_exposure[child.id]} for child in children]
        nodes += [{"id": f"target:{item.id}", "kind": "host", "name": item.name or item.value, "value": item.value, "target_id": str(item.id),
                   "ports": item.ports, "exposure": _target_result(item, latest)} for item in targets]
        if focus_target_id and focus_target_id not in target_ids:
            focused = get_or_404(db, Target, focus_target_id, "Target")
            nodes.append({"id": f"target:{focused.id}", "kind": "host", "name": focused.name or focused.value, "value": focused.value,
                          "target_id": str(focused.id), "ports": focused.ports, "exposure": _target_latest(db, {focused.value}).get(focused.value)})
        if mode == "network":
            nodes += [{**_device_out(item), "id": f"device:{item.id}", "kind": "device"} for item in devices]
        return {"scope": {"zone": _zone_out(db, zone)}, "mode": mode, "nodes": nodes,
                "links": [_link_out(item) for item in links], "truncated": offset + len(targets) < len(target_ids),
                "next_offset": offset + len(targets) if offset + len(targets) < len(target_ids) else None}

    if si_id:
        si = get_or_404(db, InformationSystem, si_id, "Information system")
        si_ids = {si.id, *db.execute(select(InformationSystem.id).where(InformationSystem.parent_id == si.id)).scalars()}
        child_systems = db.execute(select(InformationSystem).where(InformationSystem.parent_id == si.id).order_by(InformationSystem.name)).scalars().all()
        if si.parent_id:
            child_systems = []
        zone_candidates = db.execute(select(NetworkZone).where(NetworkZone.parent_zone_id.is_(None)).order_by(NetworkZone.name)).scalars().all()
        relevant_zone_ids = set(db.execute(select(NetworkZoneSystem.zone_id).where(NetworkZoneSystem.si_id.in_(si_ids))).scalars())
        relevant_zone_ids.update(db.execute(select(NetworkZoneTarget.zone_id).join(Target, Target.id == NetworkZoneTarget.target_id)
                                            .join(ResourceSI, and_(ResourceSI.resource_id == Target.id, ResourceSI.resource_type == "target"))
                                            .where(ResourceSI.si_id.in_(si_ids))).scalars())
        # If a target/SI is associated with a nested zone, surface the root zone in the
        # SI-level map so the user can progressively enter that hierarchy.
        zone_parents = dict(db.execute(select(NetworkZone.id, NetworkZone.parent_zone_id)).all())
        for zone_id in tuple(relevant_zone_ids):
            parent_id = zone_parents.get(zone_id)
            seen: set[uuid.UUID] = set()
            while parent_id is not None and parent_id not in seen:
                seen.add(parent_id)
                relevant_zone_ids.add(parent_id)
                parent_id = zone_parents.get(parent_id)
        zones = [item for item in zone_candidates if item.id in relevant_zone_ids]
        target_list = _targets_for_si(db, si_ids)
        zone_target_ids = set(db.execute(select(NetworkZoneTarget.target_id).where(NetworkZoneTarget.zone_id.in_(relevant_zone_ids))).scalars())
        unassigned = [t for t in target_list if t.id not in zone_target_ids]
        latest = _target_latest(db, {t.value for t in target_list})
        nodes = [{"id": f"si:{child.id}", "kind": "si", "name": child.name, "si_id": str(child.id),
                  "exposure": _exposure(_targets_for_si(db, {child.id}), latest)} for child in child_systems]
        group_ids = set(db.execute(select(ResourceSI.resource_id).where(ResourceSI.resource_type == "group", ResourceSI.si_id.in_(si_ids))).scalars())
        if group_ids:
            groups = db.execute(select(TargetGroup).where(TargetGroup.id.in_(group_ids)).order_by(TargetGroup.name)).scalars().all()
            group_targets = {group.id: db.execute(select(Target).join(TargetGroupMember, TargetGroupMember.target_id == Target.id)
                                                   .where(TargetGroupMember.group_id == group.id)).scalars().all() for group in groups}
            nodes += [{"id": f"group:{group.id}", "kind": "group", "name": group.name, "group_id": str(group.id),
                       "count": len(group_targets[group.id]), "exposure": _exposure(group_targets[group.id], latest)} for group in groups]
        zone_exposure = _zone_exposures(db, [item.id for item in zones], latest, {target.id for target in target_list})
        nodes += [{"id": f"zone:{item.id}", "kind": "zone", "name": item.name, "zone_id": str(item.id), "zone_type": item.zone_type,
                   "cidr": item.cidr, "exposure": zone_exposure[item.id]} for item in zones]
        network_devices: list[NetworkDevice] = []
        network_links: list[NetworkLink] = []
        if mode == "network" and zones:
            network_devices = db.execute(select(NetworkDevice).where(NetworkDevice.zone_id.in_([item.id for item in zones]))
                                         .order_by(NetworkDevice.name)).scalars().all()
            device_ids = [item.id for item in network_devices]
            if device_ids:
                network_links = db.execute(select(NetworkLink).where(or_(NetworkLink.source_device_id.in_(device_ids),
                                                                         NetworkLink.target_device_id.in_(device_ids)))).scalars().all()
            nodes += [{**_device_out(item), "id": f"device:{item.id}", "kind": "device"} for item in network_devices]
        flat_targets = mode == "si" and not zones and not child_systems
        if unassigned and not expand_unassigned and not flat_targets:
            nodes.append({"id": "unassigned", "kind": "unassigned", "name": "Unassigned assets", "count": len(unassigned),
                          "exposure": _exposure(unassigned, latest)})
        if unassigned and expand_unassigned and not flat_targets:
            nodes += [{"id": f"target:{item.id}", "kind": "host", "name": item.name or item.value, "value": item.value,
                       "target_id": str(item.id), "ports": item.ports, "exposure": _target_result(item, latest)} for item in unassigned[offset:offset + limit]]
        if flat_targets and target_list:
            nodes += [{"id": f"target:{item.id}", "kind": "host", "name": item.name or item.value, "value": item.value,
                       "target_id": str(item.id), "ports": item.ports, "exposure": _target_result(item, latest)} for item in target_list[offset:offset + limit]]
        if focus_target_id and all(item.get("target_id") != str(focus_target_id) for item in nodes):
            focused = get_or_404(db, Target, focus_target_id, "Target")
            if focused.id in {item.id for item in target_list}:
                nodes.append({"id": f"target:{focused.id}", "kind": "host", "name": focused.name or focused.value, "value": focused.value,
                              "target_id": str(focused.id), "ports": focused.ports, "exposure": _target_result(focused, latest)})
        return {"scope": {"si": {"id": str(si.id), "name": si.name, "description": si.description}}, "mode": mode,
                "nodes": nodes, "links": [_link_out(item) for item in network_links],
                "truncated": (flat_targets and offset + limit < len(target_list)) or (expand_unassigned and offset + limit < len(unassigned)),
                "next_offset": offset + limit if ((flat_targets and offset + limit < len(target_list)) or (expand_unassigned and offset + limit < len(unassigned))) else None}

    systems = db.execute(select(InformationSystem).where(InformationSystem.parent_id.is_(None)).order_by(InformationSystem.name)).scalars().all()
    child_ids = db.execute(select(InformationSystem.id).where(InformationSystem.parent_id.is_not(None))).scalars().all()
    all_si_ids = {item.id for item in systems} | set(child_ids)
    targets = _targets_for_si(db, all_si_ids)
    all_targets = db.execute(select(Target).order_by(Target.value)).scalars().all()
    assigned_target_ids = {item.id for item in targets}
    unassigned = [item for item in all_targets if item.id not in assigned_target_ids]
    latest = _target_latest(db, {item.value for item in all_targets})
    children_by_parent: dict[uuid.UUID, set[uuid.UUID]] = {}
    for child_id, parent_id in db.execute(select(InformationSystem.id, InformationSystem.parent_id).where(InformationSystem.parent_id.is_not(None))):
        children_by_parent.setdefault(parent_id, set()).add(child_id)
    nodes = []
    for item in systems:
        member_ids = {item.id} | children_by_parent.get(item.id, set())
        member_targets = _targets_for_si(db, member_ids)
        nodes.append({"id": f"si:{item.id}", "kind": "si", "name": item.name, "si_id": str(item.id),
                      "child_count": len(children_by_parent.get(item.id, set())), "exposure": _exposure(member_targets, latest)})
    focus_is_unassigned = bool(focus_target_id and any(item.id == focus_target_id for item in unassigned))
    if expand_unassigned:
        page = unassigned[offset:offset + limit]
        nodes += [{"id": f"target:{item.id}", "kind": "host", "name": item.name or item.value, "value": item.value,
                   "target_id": str(item.id), "ports": item.ports, "exposure": _target_result(item, latest)} for item in page]
    elif len(unassigned) == 1 and not focus_is_unassigned:
        item = unassigned[0]
        nodes.append({"id": f"target:{item.id}", "kind": "host", "name": item.name or item.value, "value": item.value,
                      "target_id": str(item.id), "ports": item.ports, "exposure": _target_result(item, latest)})
    elif unassigned and not focus_is_unassigned:
        nodes.append({"id": "unassigned", "kind": "unassigned", "name": "Unassigned assets", "count": len(unassigned),
                      "exposure": _exposure(unassigned, latest)})
    if focus_target_id:
        focused = get_or_404(db, Target, focus_target_id, "Target")
        if all(node.get("target_id") != str(focused.id) for node in nodes):
            nodes.append({"id": f"target:{focused.id}", "kind": "host", "name": focused.name or focused.value, "value": focused.value,
                          "target_id": str(focused.id), "ports": focused.ports,
                          "exposure": _target_latest(db, {focused.value}).get(focused.value)})
    truncated = expand_unassigned and offset + limit < len(unassigned)
    return {"scope": {}, "mode": mode, "nodes": nodes, "links": [], "truncated": truncated,
            "next_offset": offset + limit if truncated else None,
            "totals": {"systems": len(systems), "targets": len(all_targets)}}


@router.get("/hosts/{target_id}", response_model=HostDetailOut)
def host_detail(target_id: uuid.UUID, db: DbSession = Depends(get_db), _: User = Depends(reader)) -> dict:
    target = get_or_404(db, Target, target_id, "Target")
    latest = _target_result(target, _target_latest(db, {target.value}))
    si_ids = [str(x) for x in db.execute(select(ResourceSI.si_id).where(ResourceSI.resource_type == "target", ResourceSI.resource_id == target.id)).scalars()]
    zones = db.execute(select(NetworkZone).join(NetworkZoneTarget).where(NetworkZoneTarget.target_id == target.id).order_by(NetworkZone.name)).scalars().all()
    findings: list[dict] = []
    if latest:
        endpoints = latest["endpoints"]
        endpoint_ids = [e["endpoint_id"] for e in endpoints]
        run_id = uuid.UUID(latest["run_id"])
        findings = [{"finding_id": row.finding_id, "title": row.title, "category": row.category, "severity": row.severity,
                     "status": row.status, "evidence": row.evidence, "remediation": row.remediation,
                     "affected_endpoint_ids": [i for i in row.affected_endpoint_ids if i in endpoint_ids]}
                    for row in db.execute(select(RunFinding).where(RunFinding.run_id == run_id)).scalars()
                    if set(row.affected_endpoint_ids or []) & set(endpoint_ids)]
    return {"target": {"id": str(target.id), "name": target.name, "value": target.value, "kind": target.kind, "ports": target.ports,
                       "description": target.description, "si_ids": si_ids,
                       "zones": [{"id": str(z.id), "name": z.name} for z in zones]},
            "scan": latest, "findings": findings}


@router.get("/search", response_model=list[SearchOut])
def search(q: str = Query(min_length=2, max_length=255), limit: int = Query(default=20, ge=1, le=50),
           db: DbSession = Depends(get_db), _: User = Depends(reader)) -> list[dict]:
    needle = f"%{q.replace('%', '').replace('_', '')}%"
    tagged_targets = select(ResourceTag.resource_id).join(Tag, Tag.id == ResourceTag.tag_id).where(
        ResourceTag.resource_type == "target", Tag.name.ilike(needle)
    )
    targets = db.execute(select(Target).where(or_(Target.name.ilike(needle), Target.value.ilike(needle), Target.id.in_(tagged_targets)))
                         .order_by(Target.value).limit(limit)).scalars().all()
    systems = db.execute(select(InformationSystem).where(InformationSystem.name.ilike(needle)).order_by(InformationSystem.name).limit(limit)).scalars().all()
    zones = db.execute(select(NetworkZone).where(or_(NetworkZone.name.ilike(needle), NetworkZone.cidr.ilike(needle))).order_by(NetworkZone.name).limit(limit)).scalars().all()
    devices = db.execute(select(NetworkDevice).where(or_(NetworkDevice.name.ilike(needle), NetworkDevice.ip_address.ilike(needle))).order_by(NetworkDevice.name).limit(limit)).scalars().all()
    target_ids = [item.id for item in targets]
    target_systems: dict[uuid.UUID, list[str]] = {}
    target_zones: dict[uuid.UUID, list[str]] = {}
    if target_ids:
        for target_id, si_value in db.execute(select(ResourceSI.resource_id, ResourceSI.si_id).where(ResourceSI.resource_type == "target", ResourceSI.resource_id.in_(target_ids))):
            target_systems.setdefault(target_id, []).append(str(si_value))
        for target_id, zone_value in db.execute(select(NetworkZoneTarget.target_id, NetworkZoneTarget.zone_id).where(NetworkZoneTarget.target_id.in_(target_ids))):
            target_zones.setdefault(target_id, []).append(str(zone_value))
        for target_id, si_value in db.execute(select(NetworkZoneTarget.target_id, NetworkZoneSystem.si_id)
                                               .join(NetworkZoneSystem, NetworkZoneSystem.zone_id == NetworkZoneTarget.zone_id)
                                               .where(NetworkZoneTarget.target_id.in_(target_ids))):
            target_systems.setdefault(target_id, []).append(str(si_value))
    return ([{"kind": "host", "id": str(t.id), "name": t.name or t.value, "value": t.value,
              "si_ids": target_systems.get(t.id, []), "zone_ids": target_zones.get(t.id, [])} for t in targets]
            + [{"kind": "si", "id": str(x.id), "name": x.name} for x in systems]
            + [{"kind": "zone", "id": str(x.id), "name": x.name, "parent_zone_id": str(x.parent_zone_id) if x.parent_zone_id else None} for x in zones]
            + [{"kind": "device", "id": str(x.id), "name": x.name, "zone_id": str(x.zone_id) if x.zone_id else None} for x in devices])[:limit]


def _replace_zone_relations(db: DbSession, zone: NetworkZone, body: ZoneBody) -> None:
    si_ids, target_ids = _uuid_values(body.si_ids), _uuid_values(body.target_ids)
    primary_ids = set(body.primary_target_ids)
    if not primary_ids.issubset(set(target_ids)):
        raise HTTPException(422, "Primary placements must also be assigned to this zone")
    _validate_associations(db, si_ids, target_ids)
    if primary_ids:
        db.execute(update(NetworkZoneTarget).where(NetworkZoneTarget.target_id.in_(primary_ids), NetworkZoneTarget.zone_id != zone.id)
                   .values(primary_placement=False))
    db.execute(delete(NetworkZoneSystem).where(NetworkZoneSystem.zone_id == zone.id))
    db.execute(delete(NetworkZoneTarget).where(NetworkZoneTarget.zone_id == zone.id))
    for si in si_ids:
        db.add(NetworkZoneSystem(zone_id=zone.id, si_id=si))
    for target_id in target_ids:
        db.add(NetworkZoneTarget(zone_id=zone.id, target_id=target_id, primary_placement=target_id in primary_ids))


def _save_zone(db: DbSession, zone: NetworkZone, body: ZoneBody, actor: User, action: str) -> dict:
    _validate_zone_cycle(db, zone.id if zone.id != uuid.UUID(int=0) else None, body.parent_zone_id)
    if body.parent_zone_id == zone.id:
        raise HTTPException(422, "A zone cannot be its own parent")
    zone.name, zone.description, zone.zone_type = body.name.strip(), body.description, body.zone_type
    zone.parent_zone_id, zone.cidr = body.parent_zone_id, _validate_cidr(body.cidr)
    _replace_zone_relations(db, zone, body)
    db.add(zone)
    try:
        db.flush()
    except IntegrityError as error:
        db.rollback()
        raise HTTPException(409, "A zone with this name already exists at this level") from error
    audit.record(db, f"map.zone_{action}", actor=actor, resource_type="network_zone", resource_id=zone.id,
                 detail={"name": zone.name, "si_count": len(body.si_ids), "target_count": len(body.target_ids)})
    db.commit()
    return _zone_out(db, zone)


@router.get("/zones", response_model=list[ZoneOut])
def list_zones(db: DbSession = Depends(get_db), _: User = Depends(reader)) -> list[dict]:
    return [_zone_out(db, item) for item in db.execute(select(NetworkZone).order_by(NetworkZone.name)).scalars()]


@router.post("/zones", status_code=201, response_model=ZoneOut)
def create_zone(body: ZoneBody, db: DbSession = Depends(get_db), user: User = Depends(operator)) -> dict:
    return _save_zone(db, NetworkZone(id=uuid.uuid4()), body, user, "create")


@router.put("/zones/{zone_id}", response_model=ZoneOut)
def update_zone(zone_id: uuid.UUID, body: ZoneBody, db: DbSession = Depends(get_db), user: User = Depends(operator)) -> dict:
    return _save_zone(db, get_or_404(db, NetworkZone, zone_id, "Zone"), body, user, "update")


@router.delete("/zones/{zone_id}", status_code=204)
def delete_zone(zone_id: uuid.UUID, db: DbSession = Depends(get_db), user: User = Depends(operator)) -> None:
    zone = get_or_404(db, NetworkZone, zone_id, "Zone")
    db.delete(zone)
    audit.record(db, "map.zone_delete", actor=user, resource_type="network_zone", resource_id=zone.id, detail={"name": zone.name})
    db.commit()


def _save_device(db: DbSession, item: NetworkDevice, body: DeviceBody, user: User, action: str) -> dict:
    if body.zone_id:
        get_or_404(db, NetworkZone, body.zone_id, "Zone")
    if body.target_id:
        get_or_404(db, Target, body.target_id, "Target")
    item.name, item.device_type, item.zone_id = body.name.strip(), body.device_type, body.zone_id
    item.ip_address, item.target_id = _validate_ip(body.ip_address), body.target_id
    item.provenance, item.source, item.observed_at = body.provenance, body.source, body.observed_at
    item.confidence, item.metadata_json = _validate_confidence(body.confidence), body.metadata
    db.add(item)
    db.flush()
    audit.record(db, f"map.device_{action}", actor=user, resource_type="network_device", resource_id=item.id,
                 detail={"device_type": item.device_type, "provenance": item.provenance})
    db.commit()
    return _device_out(item)


@router.get("/devices", response_model=list[DeviceOut])
def list_devices(db: DbSession = Depends(get_db), _: User = Depends(reader)) -> list[dict]:
    return [_device_out(item) for item in db.execute(select(NetworkDevice).order_by(NetworkDevice.name)).scalars()]


@router.post("/devices", status_code=201, response_model=DeviceOut)
def create_device(body: DeviceBody, db: DbSession = Depends(get_db), user: User = Depends(operator)) -> dict:
    return _save_device(db, NetworkDevice(), body, user, "create")


@router.put("/devices/{device_id}", response_model=DeviceOut)
def update_device(device_id: uuid.UUID, body: DeviceBody, db: DbSession = Depends(get_db), user: User = Depends(operator)) -> dict:
    return _save_device(db, get_or_404(db, NetworkDevice, device_id, "Device"), body, user, "update")


@router.delete("/devices/{device_id}", status_code=204)
def delete_device(device_id: uuid.UUID, db: DbSession = Depends(get_db), user: User = Depends(operator)) -> None:
    item = get_or_404(db, NetworkDevice, device_id, "Device")
    db.delete(item)
    audit.record(db, "map.device_delete", actor=user, resource_type="network_device", resource_id=item.id)
    db.commit()


def _save_link(db: DbSession, item: NetworkLink, body: LinkBody, user: User, action: str) -> dict:
    get_or_404(db, NetworkDevice, body.source_device_id, "Source device")
    get_or_404(db, NetworkDevice, body.target_device_id, "Target device")
    item.source_device_id, item.target_device_id, item.link_type = body.source_device_id, body.target_device_id, body.link_type
    item.provenance, item.source, item.observed_at = body.provenance, body.source, body.observed_at
    item.confidence, item.description = _validate_confidence(body.confidence), body.description
    db.add(item)
    try:
        db.flush()
    except IntegrityError as error:
        db.rollback()
        raise HTTPException(409, "This network link already exists") from error
    audit.record(db, f"map.link_{action}", actor=user, resource_type="network_link", resource_id=item.id,
                 detail={"provenance": item.provenance, "source_device_id": str(item.source_device_id), "target_device_id": str(item.target_device_id)})
    db.commit()
    return _link_out(item)


@router.get("/links", response_model=list[LinkOut])
def list_links(db: DbSession = Depends(get_db), _: User = Depends(reader)) -> list[dict]:
    return [_link_out(item) for item in db.execute(select(NetworkLink).order_by(NetworkLink.created_at.desc())).scalars()]


@router.post("/links", status_code=201, response_model=LinkOut)
def create_link(body: LinkBody, db: DbSession = Depends(get_db), user: User = Depends(operator)) -> dict:
    return _save_link(db, NetworkLink(), body, user, "create")


@router.put("/links/{link_id}", response_model=LinkOut)
def update_link(link_id: uuid.UUID, body: LinkBody, db: DbSession = Depends(get_db), user: User = Depends(operator)) -> dict:
    item = get_or_404(db, NetworkLink, link_id, "Link")
    return _save_link(db, item, body, user, "update")


@router.delete("/links/{link_id}", status_code=204)
def delete_link(link_id: uuid.UUID, db: DbSession = Depends(get_db), user: User = Depends(operator)) -> None:
    item = get_or_404(db, NetworkLink, link_id, "Link")
    db.delete(item)
    audit.record(db, "map.link_delete", actor=user, resource_type="network_link", resource_id=item.id)
    db.commit()
