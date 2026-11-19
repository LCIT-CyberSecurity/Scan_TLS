# LCIT Scan TLS

LCIT Scan TLS is the LCIT platform for TLS endpoint inventory, security checks, scan scheduling, reports, and optional network protocol controls.

## Deploy

The supported Docker Sandbox and production deployment is managed by the repository bootstrap script:

```bash
./bootstrap_tls-scan-deployment.sh --mode webui install
```

See [installation and upgrades](docs/admin/install.md), [operations and backups](docs/admin/operations.md), and [secret handling](docs/admin/secrets.md).

## Use

The web UI provides target management, multiprotocol scans, policies and profiles, schedules, history, reports, and administration. User workflows are documented in the [user guide](docs/user/guide.md). The legacy standalone scanner guide is [here](docs/user/standalone-cli.md).

## Architecture and development

- [Architecture overview](docs/architecture/overview.md)
- [Data model](docs/architecture/data-model.md)
- [DNS lookalike monitoring](docs/user/dns-lookalike-monitoring.md)
- [Endpoint exposure and contextual risk](docs/user/endpoint-exposure-risk.md)
- [Greenbone target import and LST-24 rehearsal](docs/integrations/greenbone-import.md)
- [Developer setup and tests](docs/dev/contributing.md)
- [Docker and integration testing](docs/dev/testing.md)

For installation-specific secrets, backups, upgrades, and recovery, follow the admin documents above. Do not place credentials in committed files or paste them into issue comments.
