"""Exclusions: hosts, networks and names that a scan must never touch.

An entry is an IP address, a CIDR network, a fully qualified name, or a wildcard name (`*.example.org`, which covers every
name below `example.org` but not `example.org` itself). The entries are validated as strictly as the targets: they
may reach nmap's command line (`--exclude`), so nothing but addresses, networks and host names is accepted.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from .models import ConfigError

_NAME_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?(\.[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)*$")
MAX_ENTRIES = 500


def parse_entry(raw: str) -> str:
    """Normalised entry, or ConfigError."""
    value = raw.strip().rstrip(".") if isinstance(raw, str) else ""
    if not value or value.startswith("-") or " " in value or "," in value:
        raise ConfigError(f"invalid exclusion: {raw!r}")
    if value.startswith("*."):
        if not _NAME_RE.match(value[2:]) or "." not in value[2:]:
            raise ConfigError(f"invalid wildcard exclusion: {raw!r} (expected *.example.org)")
        return value.lower()
    if "/" in value:
        try:
            return str(ipaddress.ip_network(value, strict=False))
        except ValueError:
            raise ConfigError(f"invalid network in exclusions: {raw!r}") from None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if not _NAME_RE.match(value):
        raise ConfigError(f"invalid exclusion: {raw!r}")
    return value.lower()


def parse_entries(raw) -> tuple[str, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, (list, tuple)):
        raise ConfigError("scan.exclude must be a list")
    if len(raw) > MAX_ENTRIES:
        raise ConfigError(f"too many exclusions ({len(raw)} > {MAX_ENTRIES})")
    seen: dict[str, None] = {}
    for item in raw:
        seen[parse_entry(item)] = None
    return tuple(seen)


@dataclass
class Exclusions:
    entries: tuple[str, ...] = ()
    networks: list = field(default_factory=list, repr=False)
    names: set = field(default_factory=set, repr=False)
    suffixes: list = field(default_factory=list, repr=False)

    def __post_init__(self):
        for entry in self.entries:
            if entry.startswith("*."):
                self.suffixes.append(entry[1:])  # ".example.org"
            elif entry[0].isdigit() or ":" in entry:
                self.networks.append(ipaddress.ip_network(entry, strict=False))
            else:
                self.names.add(entry)

    def __bool__(self):
        return bool(self.entries)

    def ip_excluded(self, address: str) -> bool:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        return any(ip.version == net.version and ip in net for net in self.networks)

    def name_excluded(self, name: str) -> bool:
        lowered = (name or "").lower().rstrip(".")
        return bool(lowered) and (lowered in self.names or any(lowered.endswith(suffix) for suffix in self.suffixes))

    def classify_target(self, target: str) -> str:
        """`excluded` (drop it), `partial` (a network that overlaps an exclusion: nmap skips the excluded part) or `kept`."""
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            return "excluded" if self.name_excluded(target) else "kept"
        for excluded in self.networks:
            if excluded.version == network.version and network.subnet_of(excluded):
                return "excluded"
        if any(excluded.version == network.version and (excluded.overlaps(network)) for excluded in self.networks):
            return "partial"
        return "kept"

    def filter_targets(self, targets: list[str]) -> tuple[list[str], list[str], list[str]]:
        """(kept, removed, partial) - `partial` targets are also in `kept`."""
        kept, removed, partial = [], [], []
        for target in targets:
            state = self.classify_target(target)
            if state == "excluded":
                removed.append(target)
            else:
                kept.append(target)
                if state == "partial":
                    partial.append(target)
        return kept, removed, partial

    def nmap_argument(self) -> str:
        """Value of `nmap --exclude`: addresses and networks only.

        A name is never handed to nmap: it would exclude the address it resolves to, hence every other name that shares that
        address. Names are applied to the targets before the scan and to the host names after discovery.
        """
        return ",".join(str(n) for n in self.networks)
