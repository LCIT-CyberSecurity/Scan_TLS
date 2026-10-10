"""Target parsing and validation. Everything that reaches nmap goes through here first."""
from __future__ import annotations

import ipaddress
import re

FQDN_RE = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?(\.[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)*$"
)
PORTS_RE = re.compile(r"^[0-9]{1,5}([-,][0-9]{1,5})*$")


class TargetError(ValueError):
    pass


def normalize_target(raw: str) -> tuple[str, str]:
    """Return (value, kind) with kind in fqdn|ip|cidr, or raise TargetError."""
    value = raw.strip()
    if not value or value.startswith("-") or " " in value:
        raise TargetError(f"invalid target: {raw!r}")
    if "/" in value:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as error:
            raise TargetError(f"invalid CIDR: {raw!r}") from error
        return str(network), "cidr"
    try:
        return str(ipaddress.ip_address(value)), "ip"
    except ValueError:
        pass
    if not FQDN_RE.match(value):
        raise TargetError(f"invalid target: {raw!r}")
    return value.lower().rstrip("."), "fqdn"


def normalize_ports(raw: str) -> str:
    value = (raw or "").strip().replace(" ", "")
    if not value or value in ("fast", "all"):
        return value
    if not PORTS_RE.match(value):
        raise TargetError(f"invalid ports: {raw!r}")
    for part in re.split(r"[,]", value):
        for number in part.split("-"):
            if not 1 <= int(number) <= 65535:
                raise TargetError(f"port out of range: {number}")
        if "-" in part:
            low, high = (int(x) for x in part.split("-"))
            if low > high:
                raise TargetError(f"invalid port range: {part}")
    return value


def address_count(value: str, kind: str) -> int:
    if kind == "cidr":
        return ipaddress.ip_network(value, strict=False).num_addresses
    return 1
