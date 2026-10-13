"""What already covers a discovered name: scan definitions (direct, through a group, or through an IP / network target)
and recent completed scans. Read-only: it only informs the choice made in the import step.
"""
from __future__ import annotations

import ipaddress
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from tls_scan_app.models import (
    DefinitionGroup, DefinitionTarget, ScanDefinition, ScanRun, ScanSchedule, Target, TargetGroup, TargetGroupMember,
)

MAX_RECENT_RUNS = 500
MAX_DEFINITIONS_SHOWN = 5


def _network(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def _address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def definitions_by_target(db: DbSession, target_ids: list[uuid.UUID]) -> dict[uuid.UUID, list[dict[str, Any]]]:
    """For each target: the definitions that scan it, directly or through a group."""
    out: dict[uuid.UUID, list[dict[str, Any]]] = {}
    if not target_ids:
        return out
    scheduled = {row for row in db.execute(select(ScanSchedule.definition_id).where(ScanSchedule.active.is_(True))).scalars()}
    names = {d.id: d.name for d in db.execute(select(ScanDefinition)).scalars()}

    def add(target_id: uuid.UUID, definition_id: uuid.UUID, via: str, group: str = "") -> None:
        entries = out.setdefault(target_id, [])
        if any(e["id"] == str(definition_id) for e in entries):
            return
        entries.append({"id": str(definition_id), "name": names.get(definition_id, ""), "via": via, "group": group,
                        "scheduled": definition_id in scheduled})

    wanted = set(target_ids)
    for definition_id, target_id in db.execute(select(DefinitionTarget.definition_id, DefinitionTarget.target_id)).all():
        if target_id in wanted:
            add(target_id, definition_id, "target")
    group_names = {g.id: g.name for g in db.execute(select(TargetGroup)).scalars()}
    members: dict[uuid.UUID, list[uuid.UUID]] = {}
    for group_id, target_id in db.execute(select(TargetGroupMember.group_id, TargetGroupMember.target_id)).all():
        if target_id in wanted:
            members.setdefault(group_id, []).append(target_id)
    for definition_id, group_id in db.execute(select(DefinitionGroup.definition_id, DefinitionGroup.group_id)).all():
        for target_id in members.get(group_id, []):
            add(target_id, definition_id, "group", group_names.get(group_id, ""))
    return out


def network_targets(db: DbSession) -> list[tuple[Any, Target]]:
    """Targets that are an address or a network: they cover any discovered name that resolves inside them."""
    out = []
    for target in db.execute(select(Target).where(Target.kind.in_(("ip", "cidr")))).scalars():
        net = _network(target.value)
        if net is not None:
            out.append((net, target))
    return out


def recent_runs(db: DbSession, days: int) -> tuple[dict[str, dict[str, Any]], list[tuple[Any, dict[str, Any]]]]:
    """Newest completed run per scanned value (fqdn / ip) and per scanned network, within the last `days`."""
    cutoff = datetime.now(UTC) - timedelta(days=days)
    rows = db.execute(select(ScanRun).where(ScanRun.status.in_(("completed", "partial")), ScanRun.finished_at >= cutoff)
                      .order_by(ScanRun.finished_at.desc()).limit(MAX_RECENT_RUNS)).scalars().all()
    by_value: dict[str, dict[str, Any]] = {}
    networks: list[tuple[Any, dict[str, Any]]] = []
    for run in rows:
        info = {"run_id": str(run.id), "name": run.name, "finished_at": run.finished_at.isoformat() if run.finished_at else None}
        for pass_ in (run.config_snapshot or {}).get("passes", []):
            for value in pass_.get("targets", []):
                value = str(value).lower()
                if "/" in value:
                    net = _network(value)
                    if net is not None:
                        networks.append((net, info))
                else:
                    by_value.setdefault(value, info)
    return by_value, networks


def annotate(db: DbSession, items: list[dict[str, Any]], recent_days: int) -> None:
    """Add `coverage` to each reconciled item, in place.

    covered: a definition scans it (or the address it resolves to); recently_scanned: a completed run did within `recent_days`;
    shared_address: the addresses it resolves to are scanned under another name (several names, one access point).
    """
    matched = [uuid.UUID(m["id"]) for item in items for m in item["matches"]]
    by_target = definitions_by_target(db, matched)
    nets = network_targets(db)
    net_definitions = definitions_by_target(db, [t.id for _, t in nets]) if nets else {}
    by_value, run_networks = recent_runs(db, recent_days)
    for item in items:
        definitions: list[dict[str, Any]] = []
        for match in item["matches"]:
            for entry in by_target.get(uuid.UUID(match["id"]), []):
                if not any(e["id"] == entry["id"] for e in definitions):
                    definitions.append(entry)
        shared: list[str] = []
        addresses = [a for a in (_address(ip) for ip in item["ips"]) if a is not None]
        for net, target in nets:
            if any(a in net for a in addresses):
                shared.append(target.value)
                for entry in net_definitions.get(target.id, []):
                    if not any(e["id"] == entry["id"] for e in definitions):
                        definitions.append({**entry, "via": "address", "group": target.value})
        last = by_value.get(item["fqdn"]) or next((by_value[ip] for ip in item["ips"] if ip in by_value), None)
        if last is None:
            last = next((info for net, info in run_networks if any(a in net for a in addresses)), None)
        item["coverage"] = {
            "covered": bool(definitions), "definitions": definitions[:MAX_DEFINITIONS_SHOWN], "definitions_total": len(definitions),
            "shared_address": shared[:5], "recently_scanned": last is not None, "last_scan": last,
        }
