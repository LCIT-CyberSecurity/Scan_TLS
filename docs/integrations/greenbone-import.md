# OpenVAS / Greenbone imports

Administration → Imports provides two sources for the same preview and importer:

- GMP over TLS is recommended. Retrieval is read-only and runs in the TLS Scan worker.
- GMP XML response documents can be uploaded when the Greenbone server is unreachable.

Neither path imports scan credentials, NVTs, vulnerability reports, or runs scans. A selected Greenbone Task can create a TLS Scan definition only after the administrator explicitly chooses an existing published TLS Scan profile and one or more published policies. A Greenbone scan configuration is context only; it is never misrepresented as a TLS Scan profile. Schedules are shown but are not created or activated. TCP ports from a selected Port List are normalized; UDP ports are ignored. Exclusions are displayed as warnings and are not translated into a TLS Scan exclusion automatically.

## GMP access and secrets

Create a dedicated Greenbone account (for example tls-scan-import) with read-only visibility of Targets, Tasks, Port Lists, Scan Configurations, Schedules, and Tags. The exact role/permissions vary with gvmd release and local RBAC; verify each get_* command with the account. Do not use the Greenbone administrator account. The importer never calls GMP create, modify, delete, or start-task commands and does not read scan credentials.

The backend must be able to reach gvmd from its container. GMP is not the Greenbone web UI or a REST/JSON API. Some Greenbone Community Edition deployments expose only a Unix socket; this first release supports TLS transport only. Do not expose GMP to the public Internet. Prefer a private network or protected tunnel and configure the exact destination hostname/IP in TLS_SCAN_GREENBONE_ALLOWED_HOSTS (comma-separated if multiple administrative endpoints are intentionally allowed).

Configure the GMP login secret through the deployment secret mechanism, not the UI or database:

    TLS_SCAN_GREENBONE_ALLOWED_HOSTS=greenbone.internal
    TLS_SCAN_GREENBONE_USERNAME=tls-scan-import
    TLS_SCAN_GREENBONE_PASSWORD_FILE=/run/secrets/greenbone_password
    TLS_SCAN_GREENBONE_CA_FILE=/run/secrets/greenbone_ca.pem
    # Optional mutual-TLS files, only if the gvmd endpoint requires a client certificate:
    # TLS_SCAN_GREENBONE_CLIENT_CERT_FILE=/run/secrets/greenbone_client.crt
    # TLS_SCAN_GREENBONE_CLIENT_KEY_FILE=/run/secrets/greenbone_client.key

The CA and client-certificate paths refer to files mounted into both API and worker containers. Server certificate verification is always enabled. GMP application credentials remain distinct from TLS transport credentials. The UI stores only connection label, host, port, username, and timeout in PostgreSQL; it never returns the password or certificate material. The configured host must exactly match the server-side allowlist.

Use Administration → Imports → OpenVAS / Greenbone → Test connection to inspect DNS, TCP, TLS, GMP, authentication, read permissions, and visible resource counts. A passing TCP or TLS step alone does not mean the GMP login works.

## XML fallback

Upload one or more GMP XML response documents for Targets, Tasks, Port Lists, Scan Configurations, Schedules, or Tags. The upload accepts GMP configuration responses, not vulnerability reports. Documents are size-bounded and parsed with entity expansion disabled. A second upload of identical content has a stable source identity.

For a one-off export, use an isolated gvm-tools configuration file readable only by the operator (mode 0600) rather than putting a password in command arguments or shell history. gvm-cli reads its defaults from ~/.config/gvm-tools.conf; the [gmp] and [tls] sections hold credentials and transport settings. Example read requests:

    gvm-cli -c /secure/path/gvm-tools.conf tls --hostname greenbone.internal --xml '<get_targets/>'
    gvm-cli -c /secure/path/gvm-tools.conf tls --hostname greenbone.internal --xml '<get_tasks/>'
    gvm-cli -c /secure/path/gvm-tools.conf tls --hostname greenbone.internal --xml '<get_port_lists/>'
    gvm-cli -c /secure/path/gvm-tools.conf tls --hostname greenbone.internal --xml '<get_scan_configs/>'
    gvm-cli -c /secure/path/gvm-tools.conf tls --hostname greenbone.internal --xml '<get_schedules/>'
    gvm-cli -c /secure/path/gvm-tools.conf tls --hostname greenbone.internal --xml '<get_tags/>'

Save each response as an XML file and upload them together. Do not use --gmp-password on a command line; process arguments may be visible to other local users. Review the exported XML before upload and protect/delete temporary files according to local policy.

## Matching and import behavior

Both modes normalize hosts through the TLS Scan target normalizer. A multi-host Greenbone Target becomes one TLS Scan target per valid IP/FQDN/CIDR host, and its Target name is proposed as a group. Matching uses the existing (value, ports) identity. Existing target names, descriptions, ports, tags, SI assignments, and group membership are not overwritten. Existing groups are reused by exact name and receive only additive memberships. New targets receive the Import OpenVAS tag by default; existing targets are not retagged.

Review the preview and explicitly select targets before applying. For selected Tasks, choose an existing published profile and policy set; tasks whose Target is missing are not selectable. Their definitions reference only the selected TLS Scan targets, preserve the Greenbone Task UUID as provenance, and are reused on subsequent imports rather than overwritten. The dry-run endpoint makes no inventory changes. Source UUIDs and TLS Scan object IDs are stored separately from the display tag for repeat imports. The history records mode, user, date, status, and object counts. Scan Configurations, Tags, and Schedules are displayed for context, but their engine-specific contents and scheduling rules are not copied. No Greenbone schedule is imported or enabled.

## Verification

Automated XML tests use fixtures; GMP behavior is exercised with mocked python-gvm in the test suite. A real Greenbone instance is optional and was not required for CI. python-gvm supports GMP over TLS, SSH, and Unix socket transports; this first implementation intentionally enables TLS only. Consult the official [python-gvm connection API](https://greenbone.github.io/python-gvm/api/connections.html), [python-gvm usage](https://greenbone.github.io/python-gvm/usage.html), and [gvm-tools CLI](https://greenbone.github.io/gvm-tools/tools.html) docs for release-specific behavior.
