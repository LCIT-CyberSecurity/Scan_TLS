"""Common model of DNS observations, and the DNS lookup abstraction (bounded, cached, injectable)."""
from __future__ import annotations

import asyncio
import ipaddress
from dataclasses import dataclass, field
from typing import Any, Protocol

import dns.asyncresolver
import dns.exception
import dns.name
import dns.rdatatype
import dns.resolver

from .policy import MAX_NAMES, in_scope, valid_host

HOST_TYPES = ("A", "AAAA", "CNAME")


@dataclass
class Answer:
    values: list[str]
    canonical: str = ""  # target of the CNAME chain, when the name is an alias


class LookupFailure(Exception):
    """kind: nxdomain | nodata | timeout | error"""

    def __init__(self, kind: str, detail: str = "") -> None:
        super().__init__(f"{kind}: {detail}" if detail else kind)
        self.kind = kind


class Lookup(Protocol):
    queries: int

    async def query(self, name: str, rdtype: str) -> Answer: ...


class DnsLookup:
    """Async resolver bound to one fixed server (or the worker's configuration): concurrency cap, per-query timeout, bounded cache."""

    def __init__(self, server: tuple[str, int] | None = None, timeout: float = 5.0, concurrency: int = 20, cache_size: int = 20000) -> None:
        self.resolver = dns.asyncresolver.Resolver(configure=server is None)
        if server:
            self.resolver.nameservers = [server[0]]
            self.resolver.port = server[1]
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout * 2
        self.resolver.use_edns(0)
        self.sem = asyncio.Semaphore(concurrency)
        self.cache: dict[tuple[str, str], Answer | LookupFailure] = {}
        self.cache_size = cache_size
        self.queries = 0

    async def query(self, name: str, rdtype: str) -> Answer:
        key = (name.lower(), rdtype)
        hit = self.cache.get(key)
        if hit is not None:
            if isinstance(hit, LookupFailure):
                raise hit
            return hit
        async with self.sem:
            self.queries += 1
            try:
                response = await self.resolver.resolve(name, rdtype, raise_on_no_answer=True)
                canonical = response.canonical_name.to_text().rstrip(".").lower()
                values = [item.to_text().rstrip(".") if rdtype != "TXT" else item.to_text() for item in response]
                result: Answer | LookupFailure = Answer(values, canonical if canonical != name.lower().rstrip(".") else "")
            except dns.resolver.NXDOMAIN:
                result = LookupFailure("nxdomain")
            except dns.resolver.NoAnswer:
                result = LookupFailure("nodata")
            except (dns.exception.Timeout, TimeoutError, asyncio.TimeoutError):
                result = LookupFailure("timeout")
            except (dns.resolver.NoNameservers, dns.exception.DNSException, OSError) as error:
                result = LookupFailure("error", type(error).__name__)
        if len(self.cache) < self.cache_size:
            self.cache[key] = result
        if isinstance(result, LookupFailure):
            raise result
        return result


async def try_query(lookup: Lookup, name: str, rdtype: str) -> Answer | None:
    """The answer, or None when the name/type simply does not exist; transport failures propagate as LookupFailure."""
    try:
        return await lookup.query(name, rdtype)
    except LookupFailure as failure:
        if failure.kind in ("nxdomain", "nodata"):
            return None
        raise


@dataclass
class Observation:
    fqdn: str
    in_scope: bool
    types: set[str] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)
    cnames: set[str] = field(default_factory=set)
    sources: dict[str, set[str]] = field(default_factory=dict)   # method -> details (server, record type)
    roles: set[str] = field(default_factory=set)                 # apex | ns | mx | srv
    resolved: bool | None = None                                 # None: resolution not attempted
    wildcard: bool = False
    notes: set[str] = field(default_factory=set)                 # ptr_mismatch, ct_historical...

    def as_dict(self) -> dict[str, Any]:
        return {
            "fqdn": self.fqdn, "in_scope": self.in_scope, "types": sorted(self.types), "ips": sorted(self.ips, key=_ip_key),
            "cnames": sorted(self.cnames), "sources": sorted(self.sources), "source_details": {k: sorted(v) for k, v in sorted(self.sources.items())},
            "roles": sorted(self.roles), "resolved": self.resolved, "wildcard": self.wildcard, "notes": sorted(self.notes),
        }


def _ip_key(value: str):
    try:
        ip = ipaddress.ip_address(value)
        return (ip.version, int(ip))
    except ValueError:
        return (9, 0)


class Collector:
    """Consolidates every method's findings, one entry per name, without losing the sources."""

    def __init__(self, domain: str) -> None:
        self.domain = domain
        self.items: dict[str, Observation] = {}
        self.truncated = False

    def add(self, name: str, method: str, *, detail: str = "", types: set[str] | tuple = (), ips: set[str] | tuple = (), cnames: set[str] | tuple = (),
            roles: set[str] | tuple = (), resolved: bool | None = None) -> Observation | None:
        fqdn = valid_host(name)
        if fqdn is None:
            return None
        obs = self.items.get(fqdn)
        if obs is None:
            if len(self.items) >= MAX_NAMES:
                self.truncated = True
                return None
            obs = self.items[fqdn] = Observation(fqdn, in_scope(fqdn, self.domain))
        obs.sources.setdefault(method, set())
        if detail:
            obs.sources[method].add(detail)
        obs.types.update(types)
        obs.ips.update(ips)
        obs.cnames.update(c for c in (valid_host(c) for c in cnames) if c)
        obs.roles.update(roles)
        if resolved is not None:
            obs.resolved = resolved or bool(obs.resolved)
        return obs

    def in_scope_names(self) -> list[str]:
        return [n for n, o in self.items.items() if o.in_scope]


async def resolve_host(lookup: Lookup, collector: Collector, name: str, method: str, *, detail: str = "", roles: tuple = ()) -> Observation | None:
    """Resolve A/AAAA of a name (following aliases) and record the observation, resolved or not."""
    ips: set[str] = set()
    cnames: set[str] = set()
    types: set[str] = set()
    failed = False
    for rdtype in ("A", "AAAA"):
        try:
            answer = await try_query(lookup, name, rdtype)
        except LookupFailure:
            failed = True
            continue
        if answer:
            types.add(rdtype)
            ips.update(answer.values)
            if answer.canonical:
                cnames.add(answer.canonical)
                types.add("CNAME")
    if failed and not ips:
        return collector.add(name, method, detail=detail, roles=roles)  # resolution unknown
    return collector.add(name, method, detail=detail, types=types, ips=ips, cnames=cnames, roles=roles, resolved=bool(ips))
