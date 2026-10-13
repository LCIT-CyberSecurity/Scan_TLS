"""The discovery methods. Each one is independent, bounded and reports its own status; none is needed for the others to work."""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import secrets
import time
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import dns.exception
import dns.name
import dns.query
import dns.rdatatype
import dns.reversename
import dns.xfr
import dns.zone

from .model import Collector, Lookup, LookupFailure, resolve_host, try_query
from .policy import (
    MAX_AXFR_RRSETS, MAX_CT_RESOLVE, MAX_NAMESERVERS, DiscoveryError, in_scope, is_public_domain, parse_server, server_allowed, server_key, valid_host,
)

logger = logging.getLogger("tls_scan_app.dns_discovery")
WORDLISTS = Path(__file__).parent / "wordlists"
SRV_SERVICES = ("_ldap._tcp", "_kerberos._tcp", "_kerberos._udp", "_sip._tls", "_xmpp-client._tcp", "_xmpp-server._tcp", "_imaps._tcp", "_imap._tcp",
                "_submission._tcp", "_pop3s._tcp", "_autodiscover._tcp", "_caldavs._tcp", "_carddavs._tcp", "_https._tcp", "_gc._tcp")
CT_MAX_BYTES = 8 * 1024 * 1024
CT_TIMEOUT = 25
BATCH = 100


class Stopped(Exception):
    """Cancellation or deadline: the discovery ends with the results gathered so far."""


@dataclass
class Ctx:
    domain: str
    lookup: Lookup
    collector: Collector
    options: dict[str, Any]
    settings: dict[str, Any]
    server: tuple[str, int] | None
    deadline: float
    should_stop: Callable[[], bool]
    progress: Callable[[dict[str, Any]], None]
    transfer: Callable[..., Any] = dns.query.xfr
    ct_fetch: Callable[[str], list[str]] | None = None
    report: dict[str, dict[str, Any]] = field(default_factory=dict)
    servers: list[dict[str, Any]] = field(default_factory=list)   # per-server AXFR report (legacy key: nameservers)
    security: list[dict[str, Any]] = field(default_factory=list)
    ns_names: list[str] | None = None
    wildcard_ips: set[str] = field(default_factory=set)
    transfer_possible: bool = False

    def check(self) -> None:
        if self.should_stop():
            raise Stopped("cancelled")
        if time.monotonic() > self.deadline:
            raise Stopped("deadline")


# ---------- helpers ----------
async def nameservers(ctx: Ctx) -> list[str]:
    """NS names of the domain (memoised). NXDOMAIN ends the whole discovery; other failures leave the list empty."""
    if ctx.ns_names is not None:
        return ctx.ns_names
    try:
        answer = await ctx.lookup.query(ctx.domain, "NS")
        ctx.ns_names = sorted({v.lower().rstrip(".") for v in answer.values})
    except LookupFailure as failure:
        if failure.kind == "nxdomain":
            raise DiscoveryError("The domain does not exist") from None
        if failure.kind == "nodata":
            ctx.ns_names = []
            ctx.report.setdefault("_ns_error", {})["error"] = "The domain has no NS record (is it a delegated zone apex?)"
        else:
            ctx.ns_names = []
            ctx.report.setdefault("_ns_error", {})["error"] = f"Name-server lookup failed: {failure.kind}"
    return ctx.ns_names


async def in_batches(ctx: Ctx, items: list[Any], work: Callable[[Any], Any], label: str) -> None:
    total = len(items)
    done = 0
    for start in range(0, total, BATCH):
        ctx.check()
        await asyncio.gather(*(work(item) for item in items[start:start + BATCH]))
        done = min(total, start + BATCH)
        ctx.progress({"phase": label, "done": done, "total": total, "queries": ctx.lookup.queries, "names": len(ctx.collector.items)})


# ---------- 1. classic resolution ----------
async def classic(ctx: Ctx) -> dict[str, Any]:
    """Apex A/AAAA/NS/MX/SOA/TXT and common SRV records; MX/NS/SRV targets are kept with their role (names outside the domain are flagged, never followed)."""
    domain, found, failures = ctx.domain, 0, []
    names = await nameservers(ctx)
    if "_ns_error" in ctx.report:
        failures.append(ctx.report["_ns_error"]["error"])
    info: dict[str, Any] = {}

    async def apex(rdtype: str):
        try:
            return await try_query(ctx.lookup, domain, rdtype)
        except LookupFailure as failure:
            failures.append(f"{rdtype}: {failure.kind}")
            return None

    a, aaaa, mx, soa, txt = await asyncio.gather(apex("A"), apex("AAAA"), apex("MX"), apex("SOA"), apex("TXT"))
    ips = {v for ans in (a, aaaa) if ans for v in ans.values}
    types = {t for t, ans in (("A", a), ("AAAA", aaaa)) if ans}
    if ips:
        ctx.collector.add(domain, "dns", types=types, ips=ips, roles={"apex"}, resolved=True)
        found += 1
    if soa:
        info["soa"] = soa.values[0]
    if txt:
        info["txt_count"] = len(txt.values)  # informational only: a TXT value is never a target
    for ns in names[:MAX_NAMESERVERS * 2]:
        obs = await resolve_host(ctx.lookup, ctx.collector, ns, "dns", detail="NS", roles=("ns",))
        if obs:
            obs.types.add("NS")
            found += 1
    if mx:
        for value in mx.values:
            host = valid_host(value.split()[-1]) if value.split() else None
            if host:
                obs = await resolve_host(ctx.lookup, ctx.collector, host, "dns", detail="MX", roles=("mx",))
                if obs:
                    obs.types.add("MX")
                    found += 1

    async def srv(label: str):
        try:
            answer = await try_query(ctx.lookup, f"{label}.{domain}", "SRV")
        except LookupFailure:
            return 0
        count = 0
        for value in answer.values if answer else []:
            host = valid_host(value.split()[-1]) if value.split() else None
            if host and host != ".":
                obs = await resolve_host(ctx.lookup, ctx.collector, host, "dns", detail=f"SRV {label}", roles=("srv",))
                if obs:
                    obs.types.add("SRV")
                    count += 1
        return count

    ctx.check()
    found += sum(await asyncio.gather(*(srv(s) for s in SRV_SERVICES)))
    status = "done" if not failures or found else "failed"
    if failures and found:
        status = "partial"
    return {"status": status, "detail": "; ".join(failures[:3]), "found": found, "info": info}


# ---------- 2. zone transfer ----------
def zone_observations(zone: dns.zone.Zone, domain: str) -> list[dict[str, Any]]:
    """Names of a transferred zone: host owners (A/AAAA/CNAME) and in-zone targets of MX/NS/SRV. Wildcards and service labels are dropped."""
    out: dict[str, dict[str, Any]] = {}
    for name, node in zone.nodes.items():
        label = name.to_text()
        if label.startswith("*") or "_" in label:
            continue
        fqdn = domain if label == "@" else f"{label}.{domain}"
        types, values, cnames, ips, roles = set(), [], set(), set(), set()
        for rdataset in node.rdatasets:
            kind = dns.rdatatype.to_text(rdataset.rdtype)
            if kind in ("A", "AAAA", "CNAME"):
                types.add(kind)
                for item in rdataset:
                    text = item.to_text().rstrip(".")
                    values.append(text)
                    (cnames if kind == "CNAME" else ips).add(text)
        if types:
            out[fqdn] = {"fqdn": fqdn, "types": types, "values": values[:6], "ips": ips, "cnames": cnames, "roles": roles}
        for rdataset in node.rdatasets:
            kind = dns.rdatatype.to_text(rdataset.rdtype)
            if kind in ("MX", "NS", "SRV"):
                for item in rdataset:
                    target = item.exchange if kind == "MX" else item.target
                    text = target.to_text()
                    host = (domain if text in ("@", "") else f"{text}.{domain}") if not text.endswith(".") else text.rstrip(".")
                    if text != "." and valid_host(host) and in_scope(host.lower(), domain) and host.lower() not in out:
                        out[host.lower()] = {"fqdn": host.lower(), "types": {kind}, "values": [], "ips": set(), "cnames": set(), "roles": {kind.lower()}}
    return sorted(out.values(), key=lambda h: h["fqdn"])


def bounded_transfer(generator, limit: int):
    """Abort a zone transfer that exceeds the record budget (the transfer is read message by message)."""
    count = 0
    for message in generator:
        count += sum(len(rrset) for rrset in message.answer)
        if count > limit:
            raise MemoryError("zone transfer exceeds the record limit")
        yield message


def run_transfer(transfer, address: str, port: int, domain: str, timeout: float, lifetime: float) -> dns.zone.Zone:
    generator = transfer(address, domain, port=port, timeout=timeout, lifetime=lifetime)
    return dns.zone.from_xfr(bounded_transfer(generator, MAX_AXFR_RRSETS))


async def axfr(ctx: Ctx) -> dict[str, Any]:
    """Zone transfer from the authoritative servers and from the explicitly declared ones. A refusal is the normal answer."""
    domain = ctx.domain
    timeout = float(ctx.options.get("axfr_timeout_seconds", 8))
    lifetime = float(ctx.options.get("axfr_lifetime_seconds", 25))
    targets: list[tuple[str, str, int, str]] = []  # (label, address, port, source)
    names = await nameservers(ctx)
    for ns in names[:MAX_NAMESERVERS]:
        addresses: list[str] = []
        for rdtype in ("A", "AAAA"):
            try:
                answer = await try_query(ctx.lookup, ns, rdtype)
            except LookupFailure:
                continue
            addresses.extend(answer.values if answer else [])
        if not addresses:
            ctx.servers.append({"name": ns, "address": "", "status": "unresolved", "records": 0, "source": "ns"})
            continue
        targets.append((ns, addresses[0], 53, "ns"))
    for explicit in ctx.options.get("axfr_servers", []):
        address, port = parse_server(explicit)
        targets.append((server_key(address, port), address, port, "explicit"))
    seen: set[tuple[str, int]] = set()
    found = 0
    for label, address, port, source in targets:
        ctx.check()
        if (address, port) in seen:
            continue
        seen.add((address, port))
        entry = {"name": label, "address": address, "port": port, "status": "", "records": 0, "source": source}
        ctx.servers.append(entry)
        if not server_allowed(address):
            entry["status"] = "skipped"
            continue
        try:
            zone = await asyncio.to_thread(run_transfer, ctx.transfer, address, port, domain, timeout, lifetime)
            hosts = zone_observations(zone, domain)
            entry["status"], entry["records"] = "transferred", len(hosts)
            ctx.transfer_possible = True
            for host in hosts:
                ctx.collector.add(host["fqdn"], "axfr", detail=address, types=host["types"], ips=host["ips"], cnames=host["cnames"], roles=host["roles"],
                                  resolved=True if host["ips"] else None)
            found += len(hosts)
            if source == "ns" and _public(address):
                ctx.security.append({"kind": "axfr_open", "server": label, "address": address,
                                     "message": "A public authoritative server accepted a zone transfer: anyone can list this zone."})
        except dns.xfr.TransferError:
            entry["status"] = "refused"
        except MemoryError:
            entry["status"] = "too_large"
        except (dns.exception.Timeout, TimeoutError):
            entry["status"] = "timeout"
        except (OSError, EOFError, dns.exception.DNSException):
            entry["status"] = "unreachable"
        except Exception:  # noqa: BLE001 - a malformed server answer must never kill the worker
            logger.exception("zone transfer from %s failed", label)
            entry["status"] = "error"
    if not targets:
        reason = ctx.report.get("_ns_error", {}).get("error", "no name server to ask")
        return {"status": "skipped", "detail": reason, "found": 0}
    states = {s["status"] for s in ctx.servers}
    status = "done" if "transferred" in states or states <= {"refused", "skipped", "unresolved", "too_large"} else "partial"
    if states and states <= {"timeout", "unreachable", "error"}:
        status = "failed"
    return {"status": status, "detail": f"{sum(s['status'] == 'transferred' for s in ctx.servers)}/{len(ctx.servers)} transferred", "found": found}


def _public(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return ip.is_global


# ---------- 3. dictionary ----------
def load_words(kind: str, custom: list[str]) -> list[str]:
    if kind == "custom":
        return custom
    path = WORDLISTS / ("extended.txt" if kind == "extended" else "small.txt")
    return [w for w in path.read_text().split() if w]


async def detect_wildcard(ctx: Ctx) -> set[str]:
    """Addresses a random, certainly unregistered label resolves to. Names resolving only to these are not real inventory."""
    ips: set[str] = set()
    for _ in range(2):
        label = "wc-" + secrets.token_hex(6)
        for rdtype in ("A", "AAAA"):
            try:
                answer = await try_query(ctx.lookup, f"{label}.{ctx.domain}", rdtype)
            except LookupFailure:
                continue
            ips.update(answer.values if answer else [])
    return ips


async def dictionary(ctx: Ctx) -> dict[str, Any]:
    words = load_words(ctx.options.get("dictionary", "small"), ctx.options.get("custom_words", []))
    wildcard = await detect_wildcard(ctx)
    ctx.wildcard_ips = wildcard
    hits, filtered = [], 0
    failures = 0

    async def probe(word: str) -> None:
        nonlocal filtered, failures
        name = f"{word}.{ctx.domain}"
        ips, cnames, types = set(), set(), set()
        for rdtype in ("A", "AAAA"):
            try:
                answer = await try_query(ctx.lookup, name, rdtype)
            except LookupFailure:
                failures += 1
                continue
            if answer:
                types.add(rdtype)
                ips.update(answer.values)
                if answer.canonical:
                    cnames.add(answer.canonical)
                    types.add("CNAME")
        if not ips:
            return
        if wildcard and ips <= wildcard:
            filtered += 1
            return
        hits.append((name, types, ips, cnames))

    await in_batches(ctx, words, probe, "dictionary")
    for name, types, ips, cnames in hits:
        ctx.collector.add(name, "dictionary", detail=ctx.options.get("dictionary", "small"), types=types, ips=ips, cnames=cnames, resolved=True)
    detail = f"{len(words)} names tried"
    if wildcard:
        detail += f"; wildcard DNS detected ({filtered} answer(s) ignored)"
    status = "done"
    if failures and failures >= len(words):
        status = "failed"
    return {"status": status, "detail": detail, "found": len(hits), "wildcard": bool(wildcard), "wildcard_filtered": filtered}


# ---------- 4. Certificate Transparency ----------
CT_PROVIDERS = (
    ("crt.sh", "https://crt.sh/?q=%25.{domain}&output=json"),
    ("certspotter", "https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"),
)


def _ct_names(provider: str, data: bytes) -> set[str]:
    names: set[str] = set()
    for entry in json.loads(data):
        if provider == "crt.sh":
            names.update(line.strip().lower() for line in str(entry.get("name_value", "")).splitlines())
        else:
            names.update(str(n).strip().lower() for n in entry.get("dns_names", []))
    return names


def fetch_ct(domain: str) -> list[str]:
    """Names of the public certificates of a domain, from a public Certificate Transparency search (the first provider that answers).

    The only thing sent out is the public domain name; redirects are not followed and the response size is bounded.
    """
    errors = []
    for provider, url in CT_PROVIDERS:
        request = urllib.request.Request(url.format(domain=domain), headers={"User-Agent": "tls-scan-dns-discovery", "Accept": "application/json"})
        try:
            with urllib.request.build_opener(_NoRedirect).open(request, timeout=CT_TIMEOUT) as response:
                data = response.read(CT_MAX_BYTES + 1)
            if len(data) > CT_MAX_BYTES:
                raise ValueError("response too large")
            return sorted(_ct_names(provider, data))
        except Exception as error:  # noqa: BLE001 - try the next provider
            code = getattr(error, "code", "")
            errors.append(f"{provider}: {type(error).__name__}{f' {code}' if code else ''}")
    raise OSError("; ".join(errors))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: D401, ARG002
        return None


async def certificate_transparency(ctx: Ctx) -> dict[str, Any]:
    if not ctx.settings.get("ct_enabled", True):
        return {"status": "skipped", "detail": "disabled by the administrator", "found": 0}
    if not is_public_domain(ctx.domain):
        return {"status": "skipped", "detail": "not a public domain: it is never sent to an external service", "found": 0}
    fetch = ctx.ct_fetch or fetch_ct
    try:
        raw = await asyncio.wait_for(asyncio.to_thread(fetch, ctx.domain), timeout=CT_TIMEOUT + 5)
    except Exception as error:  # noqa: BLE001 - the CT service is optional and external
        return {"status": "failed", "detail": f"Certificate Transparency service unavailable ({str(error)[:120] or type(error).__name__})", "found": 0}
    wildcards = sum(1 for n in raw if n.startswith("*."))
    names = sorted({h for h in (valid_host(n) for n in raw if not n.startswith("*.")) if h and in_scope(h, ctx.domain)})
    skipped_scope = len({n for n in raw if not n.startswith("*.")}) - len(names)
    resolvable = names[:MAX_CT_RESOLVE]

    async def verify(name: str) -> None:
        obs = await resolve_host(ctx.lookup, ctx.collector, name, "ct", detail="certificate transparency")
        if obs is not None and not obs.ips:
            obs.notes.add("ct_historical")  # a name found in a certificate, not seen resolving: not presented as active

    await in_batches(ctx, resolvable, verify, "ct")
    for name in names[MAX_CT_RESOLVE:]:
        obs = ctx.collector.add(name, "ct", detail="certificate transparency")
        if obs:
            obs.notes.add("ct_historical")
    detail = f"{len(names)} name(s) in scope"
    if wildcards:
        detail += f", {wildcards} wildcard certificate name(s) ignored"
    if skipped_scope:
        detail += f", {skipped_scope} outside the domain ignored"
    return {"status": "done", "detail": detail, "found": len(names)}


# ---------- 5. reverse DNS ----------
async def reverse(ctx: Ctx) -> dict[str, Any]:
    addresses = ctx.options.get("reverse_addresses", [])
    inconsistent = 0
    found = 0

    async def ptr(address: str) -> None:
        nonlocal inconsistent, found
        try:
            answer = await try_query(ctx.lookup, dns.reversename.from_address(address).to_text(omit_final_dot=True), "PTR")
        except LookupFailure:
            return
        for value in answer.values if answer else []:
            host = valid_host(value)
            if not host:
                continue
            ips: set[str] = set()
            for rdtype in ("A", "AAAA"):
                try:
                    forward = await try_query(ctx.lookup, host, rdtype)
                except LookupFailure:
                    continue
                ips.update(forward.values if forward else [])
            obs = ctx.collector.add(host, "reverse", detail=address, types={"PTR"}, ips=ips, resolved=bool(ips) or None)
            if obs is None:
                continue
            found += 1
            if ips and address not in ips:
                obs.notes.add("ptr_mismatch")   # the PTR does not agree with the forward resolution
                inconsistent += 1
            if not ips:
                obs.notes.add("ptr_without_forward")

    await in_batches(ctx, addresses, ptr, "reverse")
    return {"status": "done", "detail": f"{len(addresses)} address(es), {inconsistent} PTR/forward mismatch(es)", "found": found}


METHOD_FUNCTIONS = {"dns": classic, "axfr": axfr, "dictionary": dictionary, "ct": certificate_transparency, "reverse": reverse}
