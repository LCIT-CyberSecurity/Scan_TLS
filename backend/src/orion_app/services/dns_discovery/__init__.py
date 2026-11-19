"""DNS discovery: several independent methods feed one set of observations, which is then compared with the Targets inventory.

Public names of the former single module are re-exported so that existing imports keep working.
"""
from .methods import zone_observations
from .policy import DiscoveryError, normalize_domain, server_allowed
from .runner import discover_async, process_next

import dns.rdatatype
import dns.zone


def hosts_from_zone(zone: dns.zone.Zone, domain: str) -> list[dict]:
    """Host names (A / AAAA / CNAME owners) of a transferred zone; wildcards and service labels are dropped (historical shape)."""
    return [{"fqdn": h["fqdn"], "types": sorted(t for t in h["types"] if t in ("A", "AAAA", "CNAME")), "values": h["values"]}
            for h in zone_observations(zone, domain) if h["types"] & {"A", "AAAA", "CNAME"}]


__all__ = ["DiscoveryError", "discover_async", "hosts_from_zone", "normalize_domain", "process_next", "server_allowed", "zone_observations"]
