"""DNS discovery for target building: name servers of a domain and an AXFR (zone transfer) attempt.

Only the domain's own authoritative servers are asked, once each, for the domain's own zone. No brute force, no
dictionary, no recursion over other domains. A refused transfer is the normal, healthy answer; an accepted one is
reported as a finding of its own (zone transfer open to anyone). Runs in the worker (the API has no egress).
"""
from __future__ import annotations

import ipaddress
import logging
import re
from datetime import UTC, datetime, timedelta

import dns.exception
import dns.name
import dns.rdatatype
import dns.query
import dns.resolver
import dns.xfr
import dns.zone
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from tls_scan_app.models import DnsDiscovery

logger = logging.getLogger("tls_scan_app.dns_discovery")
MAX_NAMESERVERS = 6
MAX_HOSTS = 5000
RESOLVE_LIFETIME = 8
XFR_TIMEOUT = 8
XFR_LIFETIME = 25
STALE_AFTER = timedelta(minutes=5)
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class DiscoveryError(ValueError):
    pass


def normalize_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    if not domain or len(domain) > 253:
        raise DiscoveryError("Enter a domain name such as example.org")
    try:
        ipaddress.ip_address(domain)
        raise DiscoveryError("A domain name is expected, not an IP address")
    except ValueError as error:
        if isinstance(error, DiscoveryError):
            raise
    labels = domain.split(".")
    if len(labels) < 2 or not all(_LABEL.match(label) for label in labels):
        raise DiscoveryError("Enter a valid domain name such as example.org")
    return domain


def server_allowed(address: str) -> bool:
    """Never query loopback, link-local (cloud metadata), multicast or unspecified addresses."""
    ip = ipaddress.ip_address(address)
    return not (ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved)


def hosts_from_zone(zone: dns.zone.Zone, domain: str) -> list[dict]:
    """Host names (A / AAAA / CNAME owners) of a transferred zone; wildcards and service labels are dropped."""
    hosts: dict[str, dict] = {}
    for name, node in zone.nodes.items():
        label = name.to_text()
        if label.startswith("*") or "_" in label:
            continue
        fqdn = domain if label == "@" else f"{label}.{domain}"
        kinds, values = [], []
        for rdataset in node.rdatasets:
            kind = dns.rdatatype.to_text(rdataset.rdtype)
            if kind in ("A", "AAAA", "CNAME"):
                kinds.append(kind)
                values.extend(item.to_text().rstrip(".") for item in rdataset)
        if kinds:
            hosts[fqdn] = {"fqdn": fqdn, "types": sorted(set(kinds)), "values": values[:6]}
    return sorted(hosts.values(), key=lambda h: h["fqdn"])


def _addresses(resolver: dns.resolver.Resolver, host: str) -> list[str]:
    found: list[str] = []
    for kind in ("A", "AAAA"):
        try:
            found.extend(item.to_text() for item in resolver.resolve(host, kind))
        except (dns.exception.DNSException, OSError):
            continue
    return found


def discover(domain: str, resolver: dns.resolver.Resolver | None = None, transfer=dns.query.xfr) -> dict:
    resolver = resolver or dns.resolver.Resolver()
    resolver.lifetime = RESOLVE_LIFETIME
    try:
        ns_names = sorted(item.target.to_text().rstrip(".") for item in resolver.resolve(domain, "NS"))
    except dns.resolver.NXDOMAIN:
        raise DiscoveryError("The domain does not exist") from None
    except dns.resolver.NoAnswer:
        raise DiscoveryError("The domain has no NS record (is it a delegated zone apex?)") from None
    except (dns.exception.DNSException, OSError) as error:
        raise DiscoveryError(f"Name-server lookup failed: {type(error).__name__}") from None
    servers, hosts, transferred = [], [], False
    for ns in ns_names[:MAX_NAMESERVERS]:
        addresses = _addresses(resolver, ns)
        if not addresses:
            servers.append({"name": ns, "address": "", "status": "unresolved", "records": 0})
            continue
        address = addresses[0]
        entry = {"name": ns, "address": address, "status": "", "records": 0}
        servers.append(entry)
        if not server_allowed(address):
            entry["status"] = "skipped"
            continue
        try:
            zone = dns.zone.from_xfr(transfer(address, domain, timeout=XFR_TIMEOUT, lifetime=XFR_LIFETIME))
            found = hosts_from_zone(zone, domain)
            entry["status"], entry["records"] = "transferred", len(found)
            transferred = True
            known = {h["fqdn"] for h in hosts}
            hosts.extend(h for h in found if h["fqdn"] not in known)
        except dns.xfr.TransferError:
            entry["status"] = "refused"
        except (dns.exception.Timeout, TimeoutError):
            entry["status"] = "timeout"
        except (OSError, EOFError, dns.exception.DNSException):
            entry["status"] = "unreachable"
        except Exception:  # noqa: BLE001 - a malformed server answer must never kill the worker
            logger.exception("zone transfer from %s failed", ns)
            entry["status"] = "error"
    truncated = len(hosts) > MAX_HOSTS
    return {"domain": domain, "nameservers": servers, "transfer_possible": transferred,
            "hosts": hosts[:MAX_HOSTS], "truncated": truncated}


def process_next(db: DbSession) -> bool:
    """Worker: fail stale runs, claim the oldest queued discovery and run it. True when one was processed."""
    cutoff = datetime.now(UTC) - STALE_AFTER
    for stale in db.execute(select(DnsDiscovery).where(DnsDiscovery.status == "running", DnsDiscovery.started_at < cutoff)).scalars():
        stale.status, stale.error, stale.finished_at = "failed", "worker lost", datetime.now(UTC)
    row = db.execute(
        select(DnsDiscovery).where(DnsDiscovery.status == "queued").order_by(DnsDiscovery.created_at).limit(1).with_for_update(skip_locked=True)
    ).scalar_one_or_none()
    if row is None:
        db.commit()
        return False
    row.status, row.started_at = "running", datetime.now(UTC)
    domain, row_id = row.domain, row.id
    db.commit()
    try:
        result, error = discover(domain), ""
    except DiscoveryError as exc:
        result, error = None, str(exc)
    except Exception:  # noqa: BLE001
        logger.exception("dns discovery %s failed", row_id)
        result, error = None, "Discovery failed"
    row = db.get(DnsDiscovery, row_id)
    row.status, row.result, row.error, row.finished_at = ("done" if result else "failed"), result, error, datetime.now(UTC)
    from tls_scan_app.services import audit

    audit.record(db, "target.discover.done", actor_label="worker", resource_type="dns_discovery", resource_id=row_id,
                 outcome="success" if result else "failure",
                 detail={"domain": domain, "transfer_possible": bool(result and result["transfer_possible"]), "hosts": len(result["hosts"]) if result else 0})
    db.commit()
    return True
