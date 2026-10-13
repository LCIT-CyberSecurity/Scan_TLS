"""Rules that bound what a discovery may ask and to whom: domains, DNS servers, perimeter, limits."""
from __future__ import annotations

import ipaddress
import re
from typing import Any

from sqlalchemy.orm import Session as DbSession

from tls_scan_app.models import SystemSetting

SETTING_KEY = "dns_discovery"
DEFAULT_SETTINGS: dict[str, Any] = {"allowed_servers": [], "ct_enabled": True}

MAX_NAMESERVERS = 6
MAX_NAMES = 5000                  # distinct names kept per discovery
MAX_AXFR_RRSETS = 50_000          # per zone transfer
MAX_CUSTOM_WORDS = 5000
MAX_REVERSE_ADDRESSES = 256
MAX_CT_RESOLVE = 500
MAX_ALLOWED_SERVERS = 50
MAX_DURATION = {"fast": 300, "advanced": 900}
METHODS = ("dns", "axfr", "dictionary", "ct", "reverse")
FAST_METHODS = ("dns", "axfr", "dictionary", "ct")
LEGACY_METHODS = ("dns", "axfr")  # what a call without the new fields did before (name servers + zone transfer)

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_HOST_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
# Names that never exist on the public Internet: a domain under one of them is never sent to an external service.
NON_PUBLIC_TLDS = frozenset({
    "local", "localhost", "lan", "home", "internal", "intranet", "corp", "private", "test", "invalid", "example", "arpa", "onion",
    "localdomain", "domain", "home.arpa", "intra", "priv", "ad", "dmz",
})
# Cloud metadata addresses that must never be used as a DNS server, besides loopback/link-local.
BLOCKED_SERVERS = frozenset({"100.100.100.200", "fd00:ec2::254", "192.0.0.192"})


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
    """Never query loopback, link-local (cloud metadata), multicast, unspecified or reserved addresses."""
    ip = ipaddress.ip_address(address)
    if str(ip) in BLOCKED_SERVERS:
        return False
    return not (ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved)


def parse_server(value: str) -> tuple[str, int]:
    """'10.0.0.53', '10.0.0.53:5353' or '[2001:db8::53]:5353' -> (address, port). Raises DiscoveryError."""
    text = value.strip()
    port = 53
    try:
        if text.startswith("["):
            host, _, rest = text[1:].partition("]")
            if rest:
                if not rest.startswith(":"):
                    raise ValueError
                port = int(rest[1:])
        elif text.count(":") == 1:
            host, _, p = text.partition(":")
            port = int(p)
        else:
            host = text
        address = str(ipaddress.ip_address(host))
    except ValueError:
        raise DiscoveryError(f"Invalid DNS server: {value!r} (expected an IP address, optionally with a port)") from None
    if not 1 <= port <= 65535:
        raise DiscoveryError(f"Invalid DNS server port: {port}")
    if not server_allowed(address):
        raise DiscoveryError(f"DNS server {address} is not allowed (loopback, link-local, multicast, reserved or metadata address)")
    return address, port


def server_key(address: str, port: int) -> str:
    return f"{address}:{port}" if ":" not in address else f"[{address}]:{port}"


def load_settings(db: DbSession) -> dict[str, Any]:
    row = db.get(SystemSetting, SETTING_KEY)
    return {**DEFAULT_SETTINGS, **(row.value if row else {})}


def validate_settings(value: dict[str, Any]) -> dict[str, Any]:
    """Administrator settings: the DNS servers a discovery may be pointed at, and the Certificate Transparency switch."""
    unknown = set(value) - set(DEFAULT_SETTINGS)
    if unknown:
        raise DiscoveryError(f"Unknown settings: {sorted(unknown)}")
    servers = value.get("allowed_servers", [])
    if not isinstance(servers, list) or len(servers) > MAX_ALLOWED_SERVERS or not all(isinstance(s, str) for s in servers):
        raise DiscoveryError(f"allowed_servers must be a list of at most {MAX_ALLOWED_SERVERS} addresses")
    normalized = []
    for item in servers:
        if not item.strip():
            continue
        key = server_key(*parse_server(item))
        if key not in normalized:
            normalized.append(key)
    ct = value.get("ct_enabled", True)
    if not isinstance(ct, bool):
        raise DiscoveryError("ct_enabled must be a boolean")
    return {"allowed_servers": normalized, "ct_enabled": ct}


def authorized_server(value: str, settings: dict[str, Any]) -> tuple[str, int]:
    """A DNS server named in a request must have been declared by an administrator."""
    address, port = parse_server(value)
    allowed = {server_key(*parse_server(s)) for s in settings.get("allowed_servers", [])}
    if server_key(address, port) not in allowed:
        raise DiscoveryError(f"DNS server {server_key(address, port)} is not authorised: an administrator must declare it in Administration > Settings > DNS discovery")
    return address, port


def is_public_domain(domain: str) -> bool:
    """Heuristic guard before anything leaves for an Internet service: private TLDs and single-label names are never public."""
    labels = domain.split(".")
    if len(labels) < 2:
        return False
    return labels[-1] not in NON_PUBLIC_TLDS and ".".join(labels[-2:]) not in NON_PUBLIC_TLDS


def in_scope(fqdn: str, domain: str) -> bool:
    return fqdn == domain or fqdn.endswith("." + domain)


def valid_host(name: str) -> str | None:
    """Normalised host name usable as a target, or None (service labels, wildcards, malformed names)."""
    host = name.strip().lower().rstrip(".")
    if not host or len(host) > 253 or host.startswith("*"):
        return None
    labels = host.split(".")
    if len(labels) < 2 or not all(_HOST_LABEL.match(label) for label in labels):
        return None
    return host


def expand_reverse(values: list[str]) -> list[str]:
    """IPs and CIDRs of a reverse lookup, expanded and bounded; sensitive addresses are refused."""
    out: list[str] = []
    for raw in values:
        text = raw.strip()
        if not text:
            continue
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError:
            raise DiscoveryError(f"Invalid address or network for reverse DNS: {raw!r}") from None
        if network.num_addresses > MAX_REVERSE_ADDRESSES:
            raise DiscoveryError(f"{text}: too many addresses for a reverse lookup (maximum {MAX_REVERSE_ADDRESSES} per discovery)")
        for ip in network:
            if ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_link_local:
                if network.num_addresses == 1:
                    raise DiscoveryError(f"{text}: reverse lookups of loopback, link-local, multicast or unspecified addresses are refused")
                continue
            out.append(str(ip))
    if len(set(out)) > MAX_REVERSE_ADDRESSES:
        raise DiscoveryError(f"Too many addresses for a reverse lookup (maximum {MAX_REVERSE_ADDRESSES} per discovery)")
    return list(dict.fromkeys(out))


def clean_words(words: list[str]) -> list[str]:
    """Custom dictionary: bounded, one DNS label per entry."""
    if len(words) > MAX_CUSTOM_WORDS:
        raise DiscoveryError(f"The custom dictionary is limited to {MAX_CUSTOM_WORDS} entries")
    out = []
    for word in words:
        label = word.strip().lower()
        if not label:
            continue
        if not _LABEL.match(label):
            raise DiscoveryError(f"Invalid dictionary entry: {word[:40]!r} (one DNS label per line)")
        out.append(label)
    return list(dict.fromkeys(out))
