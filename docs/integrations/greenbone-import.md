# OpenVAS / Greenbone target import

Administration → Imports synchronizes **target addresses only** into the TLS Scan inventory. The connector is read-only: it never starts or changes a Greenbone scan and it does not import Tasks, Groups, Port Lists, Scan Configurations, Schedules, tags, reports, NVTs or credentials. TLS Scan remains responsible for ports, profiles, policies, scan definitions and schedules.

The workflow remains **Configure → Test → Retrieve / Upload → Preview → Select → Import → History**. Every import is explicit and auditable; a dry run does not mutate the inventory.

## GMP access and secrets

Use a dedicated Greenbone account with read-only visibility of Targets. Retrieval calls `get_version`, authenticates, then calls only `get_targets`; the connection test likewise validates authentication and `get_targets` access. No other collection read operation is issued. Do not use the Greenbone administrator account.

The backend must be able to reach gvmd from its container. GMP is not the Greenbone web UI or a REST/JSON API. This connector supports TLS transport only. Do not expose GMP to the public Internet. Prefer a private network or protected tunnel and configure the exact destination hostname/IP in `TLS_SCAN_GREENBONE_ALLOWED_HOSTS` (comma-separated if multiple administrative endpoints are intentionally allowed).

Configure the GMP login secret through the deployment secret mechanism, not the UI or database:

```text
TLS_SCAN_GREENBONE_ALLOWED_HOSTS=greenbone.internal
TLS_SCAN_GREENBONE_USERNAME=tls-scan-import
TLS_SCAN_GREENBONE_PASSWORD_FILE=/run/secrets/greenbone_password
TLS_SCAN_GREENBONE_CA_FILE=/run/secrets/greenbone_ca.pem
# Optional mutual-TLS files, only if gvmd requires a client certificate:
# TLS_SCAN_GREENBONE_CLIENT_CERT_FILE=/run/secrets/greenbone_client.crt
# TLS_SCAN_GREENBONE_CLIENT_KEY_FILE=/run/secrets/greenbone_client.key
```

The CA and optional client-certificate paths refer to files mounted into API and worker containers. Server certificate verification is always enabled. GMP application credentials are separate from TLS transport credentials. The UI stores only connection label, host, port, username and timeout in PostgreSQL; it never returns the password or certificate material. The configured host must exactly match the server-side allowlist, and resolved loopback/link-local/multicast/unspecified addresses are rejected.

Use Administration → Imports → OpenVAS / Greenbone → Test connection to inspect DNS, TCP, TLS, GMP, authentication and read access to Targets. A passing TCP or TLS step alone does not mean the GMP login works.

## XML fallback

When GMP is unreachable, upload one or more GMP `get_targets_response` XML documents. Each file must contain target entries with `hosts`; a Port List is not required. Other XML response types (including Tasks and vulnerability reports) are rejected. Documents are size-bounded and parsed with entity expansion disabled. For recurring exports, keep the same target-export filename(s) so the preview can compare addresses with the previous upload; changing the file names starts a separate source history.

For a one-off export, use an isolated gvm-tools configuration file readable only by the operator (mode 0600) rather than putting a password in command arguments or shell history. Example:

```sh
gvm-cli -c /secure/path/gvm-tools.conf tls --hostname greenbone.internal --xml '<get_targets/>'
```

Save the Targets response and upload it. Do not use `--gmp-password` on a command line; process arguments may be visible to other local users. Review the XML before upload and protect/delete temporary files according to local policy.

## Matching and import behavior

Each host is normalized by the TLS Scan target normalizer as an IP address, FQDN or CIDR. Matching uses only the exact normalized address; Greenbone UUIDs, ports, DNS resolution and address containment are not identity keys. For example, an FQDN is not treated as equal to an IP it resolves to, and an IP is not treated as equal to a containing CIDR.

An address already present in TLS Scan is reused without changing any field or association: ports, name, description, tags, information-system links, groups, scan definitions and TLS configuration remain untouched. Existing ports are not expanded. New addresses are created with empty ports, which means the TLS Scan profile chooses the port scope. New targets receive the `Import OpenVAS` provenance tag and retain a Greenbone source mapping for audit and repeat imports.

Historical TLS Scan rows may contain the same normalized address with different ports. Such an address is shown as ambiguous and no row is created or modified. Repeating an import is idempotent: it does not create additional rows for addresses that already exist, even if a source UUID changed.

The preview compares normalized target addresses with the most recent snapshot of the same source and can report changed metadata or addresses absent from the latest retrieval. Absence is informational only: no target is deleted, disabled, detached from a group, or otherwise changed automatically. Invalid host values are skipped with a warning. Administrators select the addresses to add before applying the import.

## Verification

Automated tests exercise XML validation and XXE protection, target-only GMP requests with a mocked `python-gvm` connection, IP/FQDN/CIDR normalization, matching independent of ports and source UUID, unchanged existing inventory, historical ambiguous rows, repeat-import idempotence and the ADMIN-only API boundary. A live Greenbone instance is optional for CI. Consult the official [python-gvm connection API](https://greenbone.github.io/python-gvm/api/connections.html) and [gvm-tools CLI](https://greenbone.github.io/gvm-tools/tools.html) documentation for release-specific behavior.
