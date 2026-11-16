# Network map React Flow refresh

## Scope

The map renderer now uses the MIT-licensed `@xyflow/react` package. Existing TLS Scan APIs, exploration state, zone editor, search, filters, device management, and host scan detail panel remain the source of truth. No Scanopy source or AGPL code was reused.

The global SI → zone → host navigation remains progressive. Entering an IP host list groups IPv4 assets by the configured zone CIDR when it matches; otherwise it uses a visual `/24` grouping. Expanding the subnet exposes the existing host records. DNS names and IP values are shown from the map response. Host TLS state is shown only when the existing exposure response contains compliance data.

Edges are generated only from `/map/graph.links`, and are omitted if either endpoint is absent from the current device set. Subnet groups are visual groupings and do not add topology edges. Zone names continue to use the existing zone edit API.

## Validation

* `npm run build`: PASS.
* `npm test -- --reporter=dot`: PASS, 19 files / 86 tests.
* `npm run build`: PASS; Vite reports the existing large main chunk (>500 kB).
* Chromium fixture smoke: SI → zone → subnet expansion, with no page errors. Captures: `artifacts/network-map/scanopy-flow-global-1440x900.png`, `artifacts/network-map/scanopy-flow-subnet-1440x900.png`, and `artifacts/network-map/scanopy-flow-subnet-hosts-1440x900.png`.
* The existing app shell, sidebar, page header, toolbar, overview, legend, footer, and host result panel were retained. The map canvas alone changed renderer/layout.

The authenticated application E2E suite against the integrated backend was not run locally because its configured service (`https://localhost:15200`) is not running in this workspace. The Chromium smoke used a local Vite server and API-shaped fixtures.
