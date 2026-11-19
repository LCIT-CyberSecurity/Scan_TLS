# Changelog

## Unreleased

### Changed — Orion rebranding (LST-29)

- The product is renamed **Orion** (formerly *LCIT Scan TLS* / *TLS Scan*): WebUI, reports, e-mails, OpenAPI/MCP, CLI,
  documentation. Protocol identifiers (TLS checks, result fields, the `tls_scanner` engine) are unchanged.
- New identifiers: `orion_app` package, `orion.py`, `bootstrap_orion-deployment.sh`, `ORION_*` settings, Compose project,
  database and role `orion`, images `orion-backend` / `orion-webui`, `/var/lib/orion`, API/MCP keys `orion_pat_` / `orion_mcp_`,
  MCP tools `orion_*`, migration `0024_orion_product_identity`.
- Compatibility: existing installations keep their project, database, role and volumes (pinned in `.env`); `TLS_SCAN_*`
  settings, former keys, MCP tool names, session cookie, `tls_scan_app`, `tls_scan.py` and `bootstrap_tls-scan-deployment.sh`
  keep working as deprecated aliases. New bootstrap commands `migrate-config`, `migrate-orion` and `rollback-orion`.
  See [docs/admin/orion-migration.md](docs/admin/orion-migration.md).
