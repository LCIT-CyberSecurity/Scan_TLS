"""Orchestration of a discovery (async, bounded) and the worker entry point."""
from __future__ import annotations

import asyncio
import logging
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import dns.query
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from tls_scan_app.models import DnsDiscovery

from .methods import METHOD_FUNCTIONS, Collector, Ctx, Stopped
from .model import DnsLookup, Lookup
from .policy import (
    FAST_METHODS, LEGACY_METHODS, MAX_DURATION, METHODS, DiscoveryError, load_settings, parse_server,
)

logger = logging.getLogger("tls_scan_app.dns_discovery")
STALE_AFTER = timedelta(seconds=120)   # no heartbeat for that long: the worker is gone
HEARTBEAT_EVERY = 3.0
ORDER = ("dns", "axfr", "dictionary", "ct", "reverse")

DEFAULT_OPTIONS: dict[str, Any] = {
    "mode": "fast", "methods": list(LEGACY_METHODS), "dns_server": None, "axfr_servers": [], "dictionary": "small", "custom_words": [],
    "reverse_addresses": [], "timeout_seconds": 5, "concurrency": 20, "max_duration_seconds": MAX_DURATION["fast"],
}


def legacy_hosts(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The original result shape: in-scope host names with record types and a few values."""
    hosts = []
    for obs in items:
        types = [t for t in obs["types"] if t in ("A", "AAAA", "CNAME")]
        if obs["in_scope"] and types:
            hosts.append({"fqdn": obs["fqdn"], "types": types, "values": [*obs["ips"], *obs["cnames"]][:6]})
    return hosts


async def discover_async(domain: str, options: dict[str, Any], settings: dict[str, Any], *, lookup: Lookup | None = None, transfer=dns.query.xfr,
                         ct_fetch=None, should_stop=lambda: False, progress=lambda _: None) -> dict[str, Any]:
    opts = {**DEFAULT_OPTIONS, **options}
    methods = [m for m in ORDER if m in opts["methods"]]
    server = parse_server(opts["dns_server"]) if opts.get("dns_server") else None
    lookup = lookup or DnsLookup(server, float(opts["timeout_seconds"]), int(opts["concurrency"]))
    started = time.monotonic()
    collector = Collector(domain)
    ctx = Ctx(domain=domain, lookup=lookup, collector=collector, options=opts, settings=settings, server=server,
              deadline=started + float(opts["max_duration_seconds"]), should_stop=should_stop, progress=progress, transfer=transfer, ct_fetch=ct_fetch)
    reports: dict[str, dict[str, Any]] = {m: {"status": "pending", "detail": "", "found": 0} for m in METHODS if m in methods}
    stopped = ""
    for name in methods:
        reports[name]["status"] = "running"
        progress({"phase": name, "methods": reports, "names": len(collector.items), "queries": lookup.queries})
        began = time.monotonic()
        try:
            outcome = await METHOD_FUNCTIONS[name](ctx)
        except DiscoveryError:
            raise
        except Stopped as reason:
            stopped = str(reason)
            reports[name].update(status="partial", detail="interrupted: " + stopped)
            break
        except Exception as error:  # noqa: BLE001 - one failing method never prevents the others
            logger.exception("discovery method %s failed", name)
            outcome = {"status": "failed", "detail": f"unexpected error ({type(error).__name__})", "found": 0}
        outcome["duration_ms"] = int((time.monotonic() - began) * 1000)
        reports[name].update(outcome)
    for name in methods:
        if reports[name]["status"] in ("pending", "running"):
            reports[name].update(status="skipped", detail="not run: " + (stopped or "interrupted"))
    items = sorted((o.as_dict() for o in collector.items.values()), key=lambda o: o["fqdn"])
    if ctx.wildcard_ips:
        for obs in items:  # a name that only resolves to the wildcard address is flagged
            if obs["ips"] and set(obs["ips"]) <= ctx.wildcard_ips:
                obs["wildcard"] = True
    ns_reports = [{k: v for k, v in s.items() if k != "source"} | {"source": s.get("source", "ns")} for s in ctx.servers]
    return {
        "domain": domain, "mode": opts["mode"], "methods": reports, "nameservers": ns_reports, "transfer_possible": ctx.transfer_possible,
        "hosts": legacy_hosts(items)[:5000], "observations": items, "truncated": collector.truncated, "security": ctx.security,
        "partial": bool(stopped), "stopped": stopped, "queries": lookup.queries, "duration_ms": int((time.monotonic() - started) * 1000),
        "resolver": opts.get("dns_server") or "system",
    }


def failure_message(result: dict[str, Any]) -> str:
    """When nothing at all worked, say why (never an empty success)."""
    if result["observations"]:
        return ""
    reasons = [f"{name}: {r['detail']}" for name, r in result["methods"].items() if r["status"] == "failed" and r.get("detail")]
    if reasons and all(r["status"] in ("failed", "skipped") for r in result["methods"].values()):
        return "No DNS method succeeded (" + "; ".join(reasons[:3]) + ")"
    return ""


def process_next(db: DbSession, *, lookup=None, transfer=dns.query.xfr, ct_fetch=None) -> bool:
    """Worker: fail runs whose worker disappeared, claim the oldest queued discovery and run it. True when one was processed."""
    now = datetime.now(UTC)
    for stale in db.execute(select(DnsDiscovery).where(DnsDiscovery.status == "running")).scalars():
        beat = stale.heartbeat_at or stale.started_at
        if beat is not None and beat < now - STALE_AFTER:
            stale.status, stale.error, stale.finished_at = "failed", "worker lost", now
            stale.result = stale.result or {"domain": stale.domain, "partial": True, "observations": [], "hosts": [], "nameservers": [], "methods": {}}
    row = db.execute(
        select(DnsDiscovery).where(DnsDiscovery.status == "queued").order_by(DnsDiscovery.created_at).limit(1).with_for_update(skip_locked=True)
    ).scalar_one_or_none()
    if row is None:
        db.commit()
        return False
    row.status, row.started_at, row.heartbeat_at = "running", now, now
    domain, row_id, options = row.domain, row.id, dict(row.options or {})
    if row.cancel_requested:
        row.status, row.finished_at, row.error = "failed", now, "cancelled"
        db.commit()
        return True
    settings = load_settings(db)
    db.commit()
    last_beat = [time.monotonic()]

    def should_stop() -> bool:
        if time.monotonic() - last_beat[0] < 2:
            return False
        db.expire_all()
        current = db.get(DnsDiscovery, row_id)
        return bool(current and current.cancel_requested)

    def progress(info: dict[str, Any]) -> None:
        if time.monotonic() - last_beat[0] < HEARTBEAT_EVERY:
            return
        last_beat[0] = time.monotonic()
        current = db.get(DnsDiscovery, row_id)
        if current is not None:
            current.progress = info
            current.heartbeat_at = datetime.now(UTC)
            db.commit()

    try:
        result = asyncio.run(discover_async(domain, options, settings, lookup=lookup, transfer=transfer, ct_fetch=ct_fetch, should_stop=should_stop, progress=progress))
        error = failure_message(result)
    except DiscoveryError as exc:
        result, error = None, str(exc)
    except Exception:  # noqa: BLE001
        logger.exception("dns discovery %s failed", row_id)
        result, error = None, "Discovery failed"
    db.rollback()
    row = db.get(DnsDiscovery, row_id)
    cancelled = bool(row.cancel_requested)
    row.status = "done" if result and not error else "failed"
    row.result, row.error, row.finished_at, row.progress = result, error or ("cancelled" if cancelled and not result else ""), datetime.now(UTC), None
    from tls_scan_app.services import audit

    audit.record(db, "target.discover.done", actor_label="worker", resource_type="dns_discovery", resource_id=row_id,
                 outcome="success" if row.status == "done" else "failure",
                 detail={"domain": domain, "methods": {k: v["status"] for k, v in (result or {}).get("methods", {}).items()},
                         "resolver": (result or {}).get("resolver"), "transfer_possible": bool(result and result["transfer_possible"]),
                         "names": len(result["observations"]) if result else 0, "partial": bool(result and result["partial"]), "cancelled": cancelled})
    db.commit()
    return True
