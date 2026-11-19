"""Bounded, read-only SNMPv3 collection for already-authorized target records."""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from orion_app.models import NetworkDevice, SnmpDiscovery, Target
from orion_app.services import audit

logger = logging.getLogger("orion_app.snmp_discovery")

MAX_TARGETS = 100
MAX_TABLE_ROWS = 128
TIMEOUT_SECONDS = 1.5
RETRIES = 0

SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
IF_STATUS = "1.3.6.1.2.1.2.2.1.8"
IF_SPEED = "1.3.6.1.2.1.2.2.1.5"
LLDP_REMOTE = "1.0.8802.1.1.2.1.4.1.1"
LLDP_LOCAL_PORT = "1.0.8802.1.1.2.1.3.7.1.3"
LLDP_COLUMNS = {4: "chassis_id_subtype", 5: "chassis_id", 7: "port_id_subtype", 8: "port_id", 9: "system_name"}


def _text(value: Any) -> str:
    try:
        return value.prettyPrint()
    except AttributeError:
        return str(value)


def _numeric_oid(value: Any) -> str:
    """Return numeric OIDs even when PySNMP has loaded symbolic MIB names."""
    try:
        resolved = value.getOid()
        if resolved is not None:
            return ".".join(str(part) for part in resolved)
    except (AttributeError, TypeError):
        pass
    return _text(value)


def parse_lldp_rows(rows: list[tuple[str, str]], local_port_rows: list[tuple[str, str]] | None = None) -> list[dict]:
    """Parse numeric LLDP-MIB rows without depending on locally installed MIB files."""
    local_ports = {}
    for oid, value in local_port_rows or []:
        suffix = oid[len(LLDP_LOCAL_PORT) + 1:].split(".") if oid.startswith(LLDP_LOCAL_PORT + ".") else []
        if len(suffix) >= 1:
            local_ports[suffix[-1]] = value
    neighbors: dict[str, dict] = {}
    for oid, value in rows:
        if not oid.startswith(LLDP_REMOTE + "."):
            continue
        suffix = oid[len(LLDP_REMOTE) + 1:].split(".")
        if len(suffix) < 4:
            continue
        column, *indices = suffix
        if not column.isdigit() or int(column) not in LLDP_COLUMNS:
            continue
        key = ".".join(indices)
        neighbor = neighbors.setdefault(key, {"indices": indices})
        neighbor[LLDP_COLUMNS[int(column)]] = value
        neighbor["local_port"] = local_ports.get(indices[1])
    return list(neighbors.values())


async def _walk(engine: Any, auth: Any, target: Any, root: str, limit: int) -> list[tuple[str, str]]:
    from pysnmp.hlapi.v3arch.asyncio import ContextData, ObjectIdentity, ObjectType, walk_cmd

    rows: list[tuple[str, str]] = []
    async for indication, status, _index, var_binds in walk_cmd(
        engine, auth, target, ContextData(), ObjectType(ObjectIdentity(root)), lexicographicMode=False,
    ):
        if indication or status:
            break
        for oid, value in var_binds:
            rows.append((_numeric_oid(oid), _text(value)))
            if len(rows) >= limit:
                return rows
    return rows


async def _get(engine: Any, auth: Any, target: Any, oids: list[str]) -> dict[str, str]:
    from pysnmp.hlapi.v3arch.asyncio import ContextData, ObjectIdentity, ObjectType, get_cmd

    indication, status, _index, var_binds = await get_cmd(
        engine, auth, target, ContextData(), *(ObjectType(ObjectIdentity(oid)) for oid in oids),
    )
    if indication or status:
        return {}
    return {_numeric_oid(oid): _text(value) for oid, value in var_binds}


async def _collect_one(address: str, username: str, auth_key: str, priv_key: str, timeout_seconds: float) -> dict:
    from pysnmp.hlapi.v3arch.asyncio import (
        SnmpEngine, UsmUserData, UdpTransportTarget,
        usmHMAC192SHA256AuthProtocol, usmAesCfb128Protocol,
    )

    # A strict single IP target avoids DNS rebinding and any unbounded CIDR expansion.
    ipaddress.ip_address(address)
    engine = SnmpEngine()
    auth = UsmUserData(
        username, authKey=auth_key, privKey=priv_key,
        authProtocol=usmHMAC192SHA256AuthProtocol, privProtocol=usmAesCfb128Protocol,
    )
    transport = await UdpTransportTarget.create((address, 161), timeout=timeout_seconds, retries=RETRIES)
    try:
        base = await _get(engine, auth, transport, [SYS_DESCR, SYS_OBJECT_ID, SYS_NAME])
        interfaces: dict[str, dict] = {}
        for root, field in ((IF_NAME, "name"), (IF_DESCR, "description"), (IF_STATUS, "status"), (IF_SPEED, "speed_bps")):
            for oid, value in await _walk(engine, auth, transport, root, MAX_TABLE_ROWS):
                index = oid.rsplit(".", 1)[-1]
                interfaces.setdefault(index, {"if_index": index})[field] = value
        neighbors = parse_lldp_rows(
            await _walk(engine, auth, transport, LLDP_REMOTE, MAX_TABLE_ROWS),
            await _walk(engine, auth, transport, LLDP_LOCAL_PORT, MAX_TABLE_ROWS),
        )
        def scalar(oid: str) -> str | None:
            val = base.get(oid)
            return None if not val or "No Such" in val else val
        return {
            "address": address, "status": "observed" if base else "indeterminate",
            "sys_descr": scalar(SYS_DESCR), "sys_object_id": scalar(SYS_OBJECT_ID),
            "system_name": scalar(SYS_NAME),
            "interfaces": list(interfaces.values()), "neighbors": neighbors,
            "observed_at": datetime.now(UTC).isoformat(),
        }
    finally:
        engine.close_dispatcher()


async def collect(addresses: list[str], username: str, auth_key: str, priv_key: str,
                  timeout_seconds: float = TIMEOUT_SECONDS, concurrency: int = 10) -> list[dict]:
    if not username or not auth_key or not priv_key:
        raise ValueError("SNMPv3 authPriv is not configured on the server")
    if not addresses or len(addresses) > MAX_TARGETS:
        raise ValueError(f"Select between 1 and {MAX_TARGETS} authorized target addresses")
    semaphore = asyncio.Semaphore(max(1, min(10, concurrency)))

    async def bounded(address: str) -> dict:
        async with semaphore:
            try:
                return await asyncio.wait_for(_collect_one(address, username, auth_key, priv_key, timeout_seconds), timeout=timeout_seconds * 4)
            except (Exception, asyncio.TimeoutError):
                return {"address": address, "status": "indeterminate", "error": "No SNMP response or unsupported device",
                        "interfaces": [], "neighbors": [], "observed_at": datetime.now(UTC).isoformat()}

    tasks = [asyncio.create_task(bounded(address)) for address in addresses]
    done, pending = await asyncio.wait(tasks, timeout=90)
    for task in pending:
        task.cancel()
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)
    completed = await asyncio.gather(*done, return_exceptions=True)
    by_address: dict[str, dict] = {}
    for result in completed:
        if isinstance(result, dict):
            by_address[result["address"]] = result
    return [by_address.get(address, {"address": address, "status": "indeterminate",
                                     "error": "Overall SNMP discovery time budget reached", "interfaces": [],
                                     "neighbors": [], "observed_at": datetime.now(UTC).isoformat()})
            for address in addresses]


def process_next(db: DbSession, settings) -> bool:
    """Worker-side queue consumer. Network traffic is emitted only from the scan worker."""
    now = datetime.now(UTC)
    stale_before = now - timedelta(seconds=120)
    for stale in db.execute(select(SnmpDiscovery).where(SnmpDiscovery.status == "running")).scalars():
        if (stale.heartbeat_at or stale.started_at or stale.created_at) < stale_before:
            stale.status, stale.error, stale.finished_at = "failed", "worker lost", now
    row = db.execute(select(SnmpDiscovery).where(SnmpDiscovery.status == "queued")
                     .order_by(SnmpDiscovery.created_at).limit(1).with_for_update(skip_locked=True)).scalar_one_or_none()
    if row is None:
        db.commit()
        return False
    row.status = "running"
    row.started_at = row.heartbeat_at = now
    row_id, target_ids, options = row.id, list(row.target_ids or []), dict(row.options or {})
    db.commit()

    try:
        targets = db.execute(select(Target).where(Target.id.in_([uuid.UUID(value) for value in target_ids]))).scalars().all()
        by_id = {str(target.id): target for target in targets}
        addresses = []
        ordered_targets = []
        for target_id in target_ids:
            target = by_id.get(target_id)
            if target is None:
                continue
            address = str(ipaddress.ip_address(target.value.strip("[]")))
            addresses.append(address)
            ordered_targets.append(target)
        results = asyncio.run(collect(addresses, settings.snmp_v3_username, settings.snmp_v3_auth_key,
                                      settings.snmp_v3_priv_key,
                                      timeout_seconds=float(options.get("timeout_seconds", 2)),
                                      concurrency=int(options.get("concurrency", 5))))
        devices = db.execute(select(NetworkDevice)).scalars().all()
        devices_by_target = {device.target_id: device for device in devices if device.target_id}
        by_address = {item["address"]: item for item in results}
        items = []
        for target in ordered_targets:
            address = str(ipaddress.ip_address(target.value.strip("[]")))
            item = {"target_id": str(target.id), "target": target.value, **by_address[address]}
            existing = devices_by_target.get(target.id)
            item["inventory_status"] = "new" if existing is None else (
                "enrichable" if existing.provenance == "OBSERVED" and existing.source.startswith("SNMPv3") else "conflict"
            )
            item["inventory_device_id"] = str(existing.id) if existing else None
            for neighbor in item.get("neighbors", []):
                chassis = neighbor.get("chassis_id", "").strip()
                identity = f"{neighbor.get('chassis_id_subtype', '')}:{chassis}"
                known = next((device for device in devices if (device.metadata_json or {}).get("lldp_chassis_identity") == identity), None) if chassis else None
                neighbor["inventory_status"] = "existing" if known else "new"
            items.append(item)
        result = {"items": items}
        error = ""
    except Exception:  # noqa: BLE001
        logger.exception("SNMP discovery %s failed", row_id)
        result, error = None, "SNMP discovery failed; check worker logs and target reachability"
    db.rollback()
    row = db.get(SnmpDiscovery, row_id)
    row.status = "done" if result is not None else "failed"
    row.result, row.error = result, error
    row.finished_at = datetime.now(UTC)
    row.heartbeat_at = row.finished_at
    audit.record(db, "map.snmp_discover.done", actor_label="worker", resource_type="snmp_discovery", resource_id=row_id,
                 outcome="success" if result is not None else "failure",
                 detail={"targets": len(target_ids), "observed": sum(1 for item in (result or {}).get("items", []) if item.get("status") == "observed"),
                         "protocol": "SNMPv3"})
    db.commit()
    return True
