# OpenVAS / Greenbone target import

Administration → Imports synchronizes **target addresses only** into the TLS Scan inventory. The connector is read-only: it never starts or changes a Greenbone scan and it does not import Tasks, Groups, Port Lists, Scan Configurations, Schedules, tags, reports, NVTs or credentials. TLS Scan remains responsible for ports, profiles, policies, scan definitions and schedules.

The workflow remains **Configure → Test → Retrieve / Upload → Preview → Select → Import → History**. Every import is explicit and auditable; a dry run does not mutate the inventory. TLS Scan schedule definitions remain separate and editable in **Planifications**; Greenbone schedules are never imported or changed.

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

The Docker backend suite exercises XML validation and XXE protection, target-only GMP requests with a mocked `python-gvm` connection, IP/FQDN/CIDR normalization, matching independent of ports and source UUID, unchanged existing inventory, historical ambiguous rows, repeat-import idempotence and the ADMIN-only API boundary. It also verifies that an existing DNS schedule is updated in place by an operator while a regular user is denied.

For a live GMP rehearsal, use a separate test-only TLS Scan database and Docker network, a Greenbone account with read-only visibility of only the disposable Targets, and a mounted CA/password file. Seed one Target matching an existing TLS Scan record and one new in-scope address. Do not start a Greenbone scanner or task. Verify the connection steps, preview and dry-run, selectively import the new address, confirm the existing record and its group/SI links are unchanged, repeat retrieval/import, then remove only the disposable source Target and confirm the TLS Scan target remains. Record the target counts and result without exporting secrets. Never attach the live rehearsal to the persistent Sandbox database. The repository's isolated backend tests can be run with `ops/dev/test-stack.sh`.

Regression check for schedule editing: in **Planifications**, edit a TLS schedule and save a changed frequency or time; confirm the same schedule is updated and keeps its definition, timezone and active state. For DNS schedules, use an operator account, re-confirm authorization, and verify the options and frequency are saved to the same schedule. A Greenbone import or a missing Greenbone Target must not change any TLS Scan schedule.

Consult the official [python-gvm connection API](https://greenbone.github.io/python-gvm/api/connections.html) and [gvm-tools CLI](https://greenbone.github.io/gvm-tools/tools.html) documentation for release-specific behavior.

## LST-24 persistent Sandbox rehearsal status (2026-11-18)

The earlier disposable GMP rehearsal is recorded in Jira LST-24 comment 10762. It passed the connector and import invariants against a temporary TLS Scan database. It does **not** prove an import into the persistent Sandbox inventory.

The follow-up check on 2026-11-18 found the TLS Scan Docker Sandbox reachable on the authorized integration VM, but no OpenVAS/GVM manager was available there: no matching running or stopped container, no Greenbone Docker volume, no OpenVAS/GVM deployment directory, and no OpenVAS SSH host alias in the current SSH configuration. Only the `gvmd:stable`, `pg-gvm:stable`, and `pg-gvm-migrator:stable` images were cached; no scanner or complete Greenbone test stack was running. The VM had about 22 GB free disk, close to Greenbone's documented 20 GB minimum for the full community stack, so a full feed-backed deployment was not started. No other host was probed and no network scan was run.

The Sandbox itself was not changed by the OpenVAS rehearsal: no GMP endpoint was configured, no import was submitted, and no target or schedule was created or edited. Post-deployment inventory counts were 4 scan runs, 2 schedules, 0 endpoint exposure records, and 0 DNS lookalike monitors. The TLS Scan API, PostgreSQL, WebUI, worker, and scheduler were healthy; WebUI, readiness, and auth-provider endpoints returned HTTP 200. The live GMP connection, persistent target baseline, preview, import, idempotence, source-removal, and authenticated import WebUI scenarios remain **NOT EXECUTED**.

The Sandbox WebUI login was opened with Playwright through a temporary SSH tunnel. The test context accepted the self-signed HTTPS certificate only for that browser context; no global TLS verification setting was changed. The page returned HTTP 200 and rendered the login page. No login or authenticated import flow was attempted, and the screenshot is stored in the private execution evidence directory rather than committed because it does not show the required import preview.

### Repeat the blocked-environment check

Run these read-only checks from the authorized integration host before scheduling the recipe:

```sh
ssh vm-integrations 'docker ps -a --format "{{.Names}} {{.Status}}"'
ssh vm-integrations 'docker volume ls --format "{{.Name}}"'
ssh vm-integrations 'docker image ls --format "{{.Repository}}:{{.Tag}} {{.Size}}" | grep -Ei "greenbone|openvas|gvm"'
```

Then identify or provision the authorized **test-only** Greenbone manager and expose only its GMP TLS endpoint to the TLS Scan API container. A current manager/credential/CA is required: the TLS Scan connector supports certificate-verified GMP over TLS, not the Greenbone WebUI API or a Unix socket. Keep the GMP user read-only for Targets, mount the password and CA as secrets, configure the exact allowlisted hostname, and take the required TLS Scan database/inventory baseline before any import. Do not enable feeds/scanning or contact another LAN host until the test manager is available and the selected targets are confirmed in scope. Follow the E2E sequence above and update Jira with per-scenario evidence; do not infer a persistent import result from the previous disposable rehearsal.

### Recorded status

| Check | Result | Evidence |
| --- | --- | --- |
| LST-24 schedule edit code/test from PR #36 | PASS | Jira comment 10762; PR #36 merged at `985d553b9eb6f52480d54330ed1a23bbc2752ace` |
| Current TLS Scan Sandbox Docker health | PASS | API/DB/WebUI healthy; worker/scheduler running; restart count 0; readiness HTTP 200 |
| Current Sandbox login page visual check | PASS, login page only | Playwright response HTTP 200; self-signed HTTPS exception limited to the test context |
| Current real Docker TLS Scan → GMP connection | NOT EXECUTED | No manager container/volume/service or host alias was available |
| Persistent Sandbox inventory baseline, preview and import | NOT EXECUTED | No GMP source; no inventory mutation was made |
| Persistent idempotence/source-removal and authenticated WebUI flow | NOT EXECUTED | Depends on a real test manager and test account |
| Confluence architecture page update | NOT EXECUTED | Search returned no accessible matching Scan TLS/Greenbone pages |

Evidence time: 2026-11-18 20:45 Europe/Paris. Greenbone image digests available locally were `gvmd:stable` `sha256:6c472ffc3e6eb6d806b43ffbbe3fb6b003e986dbe4dc562ad12f4b2cda38ba98`, `pg-gvm:stable` `sha256:44bd4582dc686eb59f4a8450782acb9c1b0d1bfe107231f9625bd7dea8343b66`, and `pg-gvm-migrator:stable` `sha256:87a3309535fba950c1eb3ddd11375ff1545b33bf8c92499b6e1c51798efe214a`. Greenbone's [container guide](https://greenbone.github.io/docs/latest/22.4/container/) documents 20 GB minimum storage for the full community stack; the measured free space was 22 GB. No full stack/feed synchronization was attempted.
