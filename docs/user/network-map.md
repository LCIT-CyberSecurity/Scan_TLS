# Network Exposure Map

The map is available in **Scanning → Exposure map** for `USER` roles and above. It is an exploration view over existing TLS Scan data, not a network discovery tool.

## Explore

- The global view shows each top-level information system once. Counts include its sub-SIs, target groups and targets assigned to its explicitly associated zones; a target associated more than once is counted once within each SI and once in installation totals.
- Select an SI to open its sub-SIs, existing target groups and top-level network zones. Select a group to inspect its existing members, or a zone to open its subzones and assigned TLS targets. The network-architecture mode also shows explicitly recorded devices and their links.
- The **Systems** mode emphasizes the SI/sub-SI hierarchy. **Network architecture** prioritizes zones, declared devices and explicit links; sub-SIs remain available through Systems mode and the SI selector.
- Hosts without an associated scan are shown neutrally. A scan result is associated only with its exact scanned FQDN/IP or an address in a CIDR that was explicitly scanned. A DNS alias, shared IP, or CIDR alone does not create an observed connection.
- Open a host to see the latest completed or partial run with matching persisted endpoints, certificates, findings, freshness and a link to the full scan. Older scans are not presented as current state.
- Search accepts system, zone, host, IP, CIDR, device and target-tag text. The SI selector and exposure filter limit the visible scope. Pan, wheel zoom, zoom buttons and center controls operate on the same map.
- Exposure cards show target, scanned and unscanned counts; finding severities are shown only when persisted scan results exist. An unscanned system is neutral, not green. At SI scope, network-architecture mode groups devices only with the zone explicitly assigned to them; connection line styles distinguish observed, declared and inferred links.
- The target inventory is fetched only when an operator opens a zone/device editor, rather than on every map visit. This keeps read-only map navigation light on installations with large inventories.

## Add network context

Operators and administrators can open **Manage topology** while inside an SI:

1. Create a zone and optionally set its type, parent, CIDR, SI associations and target associations. Zone nesting is independent from the SI hierarchy; cycles are rejected.
2. Add a device such as a firewall, router, gateway, switch, load balancer, reverse proxy, server, subnet or generic device. A device may optionally reference an existing TLS Scan target.
3. Declare a device-to-device link. The API enforces foreign keys, non-self links, uniqueness and valid confidence values.

Topology records carry provenance: `DECLARED`, `OBSERVED` or `INFERRED`. Observed records require a source and observation date. Inferred records require a source and confidence. Declared topology is authored by an operator; it is never labelled as scanner-observed. Missing links do not imply isolation. The map never initiates scans, traceroutes or other network traffic.

All edits are audited. Zones/devices/links are shared organizational context, not an access-control boundary. Deleting a zone preserves child zones and devices (their parent/zone is cleared), while deleting a device deletes its attached links; targets and SI classifications are not deleted.

## API

Authenticated session routes (CSRF required for writes):

- `GET /api/map/summary`, `GET /api/map/graph`, `GET /api/map/hosts/{target_id}`, `GET /api/map/search?q=…`
- `GET|POST|PUT|DELETE /api/map/zones[/{zone_id}]`
- `GET|POST|PUT|DELETE /api/map/devices[/{device_id}]`
- `GET|POST|PUT|DELETE /api/map/links[/{link_id}]`

Reads require `USER` or higher; topology changes require `OPERATOR` or `ADMIN`. Existing authenticated roles and sessions are used unchanged.

The graph endpoint loads a level at a time. Host results are paged (500 by default, at most 2,000 per request); the response indicates truncation and supports loading the next page. TLS results are read from existing `scan_runs`, `run_endpoints` and `run_findings` data and matched to the target's requested ports. No alternate score or scan-result store is introduced.

## Visual regression checks

The CrashTest seed adds an isolated, idempotent example topology using documentation-only IP ranges. It is test data only and is never inserted into a normal installation. The Playwright Network Map journey runs a real lab TLS scan, then writes global, SI/zone and host-exposure screenshots at 1920×1080, 1440×900 and 1366×768 under `artifacts/network-map/`; Chromium and Google Chrome both exercise the map rendering. Run these browser checks only in the designated Docker integration environment, not against production data.

The checked-in screenshots are the latest reviewed rendering from the integration VM. They include a scanned TLS 443 endpoint with its persisted non-compliance and findings; the topology links shown are the declared CrashTest links, not scanner-discovered routes.
