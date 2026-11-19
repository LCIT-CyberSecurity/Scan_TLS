# LCIT Scan TLS

LCIT Scan TLS inventories network endpoints (hosts, IP addresses, subnets), checks their TLS, IPsec/IKE and SSH
configuration against your policies, and produces graded, client-ready reports. Everything is driven from a
**web interface** (WebUI); a historical [standalone CLI](docs/user/standalone-cli.md) runs the same TLS engine.

## WebUI

- **Dashboard**: compliance overview, grades, critical findings, evolution between two dates ([details](docs/user/dashboard.md)).
- **Targets**: FQDN, IP or CIDR with ports, row and bulk import, [DNS discovery](docs/user/dns-discovery.md),
  [DNS lookalike monitoring](docs/user/dns-lookalike-monitoring.md), [Greenbone import](docs/integrations/greenbone-import.md),
  [exclusions](docs/user/exclusions.md), groups, tags and SI.
- **Scans**: definitions combining TLS, [IPsec/IKE](docs/ipsec-ike.md) and SSH ([multi-technology profiles](docs/multiprotocol-scans.md)),
  live progress, cancellation, comparison with the previous run; optional [complementary TLS checks](docs/user/tls-checks.md),
  [QUIC / HTTP/3](docs/user/quic-http3.md) and [mail security checks](docs/user/mail-security.md).
- **Schedules**: once, daily, weekly, monthly or cron.
- **Results and reports**: HTML, Markdown, CSV, CycloneDX CBOM ([reports](docs/user/reports.md)),
  [endpoint exposure and contextual risk](docs/user/endpoint-exposure-risk.md), [Network Exposure Map](docs/user/network-map.md)
  with [SNMPv3 / LLDP discovery](docs/user/snmp-lldp-discovery.md).
- **Policies and profiles**: versioned, YAML import/export ([details](docs/user/policies-and-profiles.md)),
  public and corporate [trust authorities](docs/user/trust-authorities.md).
- **Access**: roles AUDITOR, USER, OPERATOR, ADMIN; local accounts, [OIDC / Entra ID](docs/integrations/entra-sso.md),
  [directory connectors](docs/integrations/directory.md); audit log and [notifications](docs/integrations/notifications.md).
- **Integrations** (off by default, read-only): [REST API](docs/integrations/external-api.md) and
  [MCP server](docs/integrations/mcp.md) with per-user revocable keys.

### Install

Linux host with Docker, the Compose plugin and `openssl`. Nothing else is installed on the host.

```bash
./bootstrap_tls-scan-deployment.sh --mode webui install
```

The script prints the URL and the initial administrator account, whose password must be changed at first sign-in.
Updates, backups, restore and uninstall: [installation](docs/admin/install.md), [operations](docs/admin/operations.md)
and [secret handling](docs/admin/secrets.md). Never commit credentials or paste them into issue comments.

### Documentation

- Users: [user guide](docs/user/guide.md) · [API results](docs/user/api-results.md)
- Administrators: [installation](docs/admin/install.md) · [operations](docs/admin/operations.md) ·
  [authentication](docs/admin/authentication.md) · [exposure risk operations](docs/admin/exposure-risk-operations.md)
- Architecture: [overview](docs/architecture/overview.md) · [data model](docs/architecture/data-model.md)
- Development: [contributing](docs/dev/contributing.md) · [tests](docs/dev/testing.md) · [CrashTest](docs/dev/crashtest.md)
- [Limitations and V2](docs/limitations.md)

## Standalone CLI

```bash
./bootstrap_tls-scan-deployment.sh --mode standalone install
.venv/bin/python tls_scan.py -p 443 example.com
```

YAML configuration, cron, exports, compliance policies, grades and examples: [standalone CLI guide](docs/user/standalone-cli.md).
