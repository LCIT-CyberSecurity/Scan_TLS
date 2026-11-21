# Orion

**See your whole network's cryptography at a glance, and know exactly what to fix.**

Orion discovers your endpoints, scans their TLS, IPsec/IKE and SSH configuration, grades them against your policies
(ANSSI references included) and turns the results into clear, client-ready reports. Everything runs in Docker and is
driven from a modern web interface. Install it, point it at a network, and get your first grades within minutes.

## What Orion scans

- **TLS / PKI**: protocols, cipher suites, certificates and chains, [trust authorities](docs/user/trust-authorities.md),
  [complementary checks](docs/user/tls-checks.md) and [QUIC / HTTP/3](docs/user/quic-http3.md).
- **IPsec / IKE**: proposals and transforms of your VPN gateways ([details](docs/ipsec-ike.md)).
- **SSH**: key exchange, ciphers, MACs and host keys, with a built-in ANSSI SSH policy
  ([multi-technology profiles](docs/multiprotocol-scans.md)).
- **Mail and DNS**: [mail security](docs/user/mail-security.md), [DNS discovery](docs/user/dns-discovery.md) and
  [lookalike domain monitoring](docs/user/dns-lookalike-monitoring.md).
- **Your existing inventory**: [Greenbone / OpenVAS import](docs/integrations/greenbone-import.md) and
  [SNMPv3 / LLDP discovery](docs/user/snmp-lldp-discovery.md) feeding a [Network Exposure Map](docs/user/network-map.md).

## The WebUI

- A **[dashboard](docs/user/dashboard.md)** that shows compliance, grades, critical findings and how they evolve.
- **Live scans**: follow progress, cancel, and compare each run with the previous one.
- **[Reports](docs/user/reports.md)** in HTML, Markdown, CSV and CycloneDX CBOM, plus
  [contextual exposure risk](docs/user/endpoint-exposure-risk.md).
- **[Versioned policies and profiles](docs/user/policies-and-profiles.md)** with YAML import and export.
- **Team-ready**: AUDITOR / USER / OPERATOR / ADMIN roles, [Entra ID / OIDC](docs/integrations/entra-sso.md) sign-in,
  audit log, [notifications](docs/integrations/notifications.md), read-only [REST API](docs/integrations/external-api.md)
  and [MCP server](docs/integrations/mcp.md).

## Scheduling

Set it and forget it: run any scan once, daily, weekly, monthly or on a cron expression. Orion always uses the latest
published policy and e-mails you when a new non-compliance appears, a certificate is about to expire or a run fails.

## Try it

On a Linux host with Docker, the Compose plugin and `openssl`:

```bash
./bootstrap_orion-deployment.sh --mode webui install
```

The script prints the URL and the initial administrator account. Then follow the
**[user guide](docs/user/guide.md)**: it walks you from your first target to your first report.

Updates, backups and restore: [installation](docs/admin/install.md), [operations](docs/admin/operations.md) and
[secret handling](docs/admin/secrets.md). Never commit credentials or paste them into issue comments.

### Documentation

- Users: [user guide](docs/user/guide.md) · [API results](docs/user/api-results.md)
- Administrators: [installation](docs/admin/install.md) · [operations](docs/admin/operations.md) ·
  [authentication](docs/admin/authentication.md) · [exposure risk operations](docs/admin/exposure-risk-operations.md)
- Architecture: [overview](docs/architecture/overview.md) · [data model](docs/architecture/data-model.md) · [secrets](docs/architecture/secrets.md)
- Development: [contributing](docs/dev/contributing.md) · [tests](docs/dev/testing.md) · [CrashTest](docs/dev/crashtest.md)
- [Limitations and V2](docs/limitations.md)

A [standalone CLI](docs/user/standalone-cli.md) (`orion.py`) runs the same TLS engine without the WebUI. Orion was
previously named *LCIT Scan TLS*; existing installations keep working ([migration](docs/admin/orion-migration.md)).
