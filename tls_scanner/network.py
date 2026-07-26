"""
Target normalization, port parsing, and DNS resolution helpers.

Called by:
- `tls_scanner.cli`, to prepare scan targets;
- `tls_scanner.config`, to validate configured ports;
- `tls_scanner.scanner`, to enrich results with FQDN values.

Produces:
- normalized target strings/lists;
- validated port selections;
- IP-to-FQDN mappings used during result collection.
"""

import argparse
import ipaddress
import socket


def parse_ports(value):
    value = value.strip().lower()
    if value in ["fast", "all"]:
        return value

    ports = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            raise argparse.ArgumentTypeError("port entries cannot be empty")

        if "-" in item:
            bounds = item.split("-")
            if len(bounds) != 2 or not all(bound.isdigit() for bound in bounds):
                raise argparse.ArgumentTypeError(f"invalid port range: {item}")
            start, end = (int(bound) for bound in bounds)
            if start > end:
                raise argparse.ArgumentTypeError(f"invalid port range: {item}")
            if start < 1 or end > 65535:
                raise argparse.ArgumentTypeError("ports must be between 1 and 65535")
        elif not item.isdigit() or not 1 <= int(item) <= 65535:
            raise argparse.ArgumentTypeError("ports must be between 1 and 65535")

        ports.append(item)

    return ",".join(ports)


def normalize_targets(targets):
    normalized_targets = [target.strip() for target in targets.split(",")]
    return " ".join(target for target in normalized_targets if target)


def resolve_fqdn(ip_address):
    try:
        fqdn = socket.gethostbyaddr(ip_address)[0].rstrip(".")
    except (socket.herror, socket.gaierror, OSError):
        return ""
    return fqdn if fqdn != ip_address else ""


def resolve_target_fqdns(targets):
    fqdn_cache = {}
    for target in normalize_targets(targets).split():
        try:
            ipaddress.ip_network(target, strict=False)
            continue
        except ValueError:
            pass

        try:
            ipaddress.ip_address(target)
            continue
        except ValueError:
            pass

        try:
            canonical_name, _, addresses = socket.gethostbyname_ex(target)
        except (socket.gaierror, OSError):
            continue

        fqdn = canonical_name.rstrip(".") if canonical_name else target.rstrip(".")
        for address in addresses:
            fqdn_cache.setdefault(address, fqdn)

    return fqdn_cache
