# Orion migration (formerly LCIT Scan TLS)

The product formerly named *LCIT Scan TLS* / *TLS Scan* is now **Orion** (canonical identifier `orion`). Orion is a
network discovery, mapping, asset inventory and multi-protocol security analysis platform (TLS/PKI, SSH, IPsec/IKE, DNS,
Greenbone/OpenVAS import). The rebranding changes product identifiers only: protocol identifiers (TLS checks, result
fields, `tls_scan` scan phase, `tls_scanner` engine, report contents about TLS) keep their meaning, and nothing that existing
installations, clients or history rely on stops working.

## What changed, and what still works

| Former name | New name | Where | Compatibility |
|---|---|---|---|
| LCIT Scan TLS, TLS Scan, `TLS SCAN` | Orion | WebUI (title, sign-in, sidebar, breadcrumb, favicon), reports, e-mails, OpenAPI/Swagger, MCP server name, CLI banner, docs | branding only |
| `bootstrap_tls-scan-deployment.sh` | `bootstrap_orion-deployment.sh` | deployment | former name kept as a forwarding alias (deprecated) |
| `tls_scan.py` | `orion.py` | Standalone CLI | former name kept, same arguments (deprecated) |
| `tls_scan_app` (Python package) | `orion_app` | backend, workers, scheduler, Alembic | `import tls_scan_app.X` and `python -m tls_scan_app.X` resolve to `orion_app.X` (deprecated, warning) |
| `tls-scan-app` (distribution) | `orion-app` | `pyproject.toml` | – |
| `TLS_SCAN_*` variables | `ORION_*` | `.env`, Compose, application | every `TLS_SCAN_X` is read when `ORION_X` is absent; `ORION_X` wins when both exist; legacy names in use are logged at start (names only) |
| Compose project `tls-scan` | `orion` | Docker | an existing installation keeps `tls-scan` (pinned in `.env`) until `migrate-orion` |
| Database / role `tls_scan` | `orion` | PostgreSQL | an existing installation keeps `tls_scan` (pinned) until `migrate-orion` |
| Images `tls-scan-backend`, `tls-scan-webui` | `orion-backend`, `orion-webui` | Docker | rebuilt by `update`; `uninstall` removes both names |
| `/var/lib/tls-scan` (in the containers) | `/var/lib/orion` | data volume mount point | same volume, report paths are stored relative to it |
| container user `tlsscan` (uid 10001) | `orion` (uid 10001) | backend image | same uid: volume ownership unchanged |
| `tls-scan-backup-<UTC>.tar.gz` | `orion-backup-<UTC>.tar.gz` | backups | former archives are restored as before |
| API keys `tls_scan_pat_…`, MCP keys `tls_scan_mcp_…` | `orion_pat_…`, `orion_mcp_…` | external API / MCP | former keys stay valid until expiry or revocation (same hash, scope, RBAC, service separation) |
| MCP tools `tls_scan_*` | `orion_*` | MCP | former names served as deprecated aliases (same handler, audited under the `orion_` name) |
| Session cookie `tls_scan_session` | `orion_session` | WebUI | a session opened before the upgrade stays valid (nobody is signed out); sign-out clears both |
| Sign-in flow cookie `tls_scan_login` | `orion_login` | SSO | a sign-in started during the upgrade (5-minute window) has to be restarted |
| Browser preferences `tls-scan.*` | `orion.*` | local storage | adopted on first read (language, theme, appearance, sidebar) |
| Built-in store *TLS Scan Public Web PKI* | *Orion Public Web PKI* | trust stores, reports | historical results keep the former name as written; both names are reserved for custom stores |
| User agents `LCIT-Scan-TLS`, `tls-scan-dns-discovery`; SMTP `EHLO tls-scan.invalid`; DNS wildcard probe `tls-scan-<hex>` | `Orion`, `orion-dns-discovery`, `EHLO orion.invalid`, `orion-<hex>` | outbound probes | – |
| Notification subjects `[TLS Scan] …` | `[Orion] …` | e-mail | adapt mail filters if any |

Kept on purpose (not product identity): the `tls_scanner` engine package and its `tls_scan` logger, the `tls_scan` scan
phase, `scan_tls_host*` functions, CycloneDX CBOM property names `scan-tls:*` (an export format consumed by other tools),
dated audit records such as `docs/dev/dependency-modernization.md`, historical rows in the database (results, notifications,
audit events) and administrator-entered values that mention the former name. The Git repository is now `LCIT-CyberSecurity/Orion` (the former URLs redirect); see the external switchover below.

Deprecation plan: the aliases (`tls_scan_app`, `tls_scan.py`, `bootstrap_tls-scan-deployment.sh`, `TLS_SCAN_*`, MCP
`tls_scan_*` tools, legacy key prefixes and session cookie) stay for at least one major version; they will be removed only
after every known deployment, client and automation has been moved and the removal has been announced.

## Upgrading an existing installation (in place)

```bash
./bootstrap_orion-deployment.sh --mode webui update        # or the former script name
```

The bootstrap recognises the installation (`TLS_SCAN_*` entries in `.env`, or volumes of the `tls-scan` project) and only
**appends** `ORION_PROJECT=tls-scan`, `ORION_DB_NAME=tls_scan`, `ORION_DB_USER=tls_scan` to `.env`. Nothing else in `.env`,
the secrets or the certificates changes; the same project, database, role and volumes are reused; the verified backup,
rebuild, migrations (including `0024`) and health checks run as for any update. Rollback: restore the backup taken by
`update` with the previous version, as for any update.

Optional, at any time: `./bootstrap_orion-deployment.sh migrate-config` renames the `TLS_SCAN_*` entries of `.env` to
`ORION_*` (values unchanged and never printed; an explicit `ORION_*` entry wins). A copy `.env.pre-orion-<UTC>` (mode 600) is
kept, and restored automatically if Compose rejects the result. Delete the copy once checked: it holds the same settings.

## Moving the data to the `orion` project and database (`migrate-orion`)

Renaming a live database or volume in place is not done. `migrate-orion` copies instead, so that the TLS Scan
installation stays intact and is the rollback:

1. the Orion images are built while TLS Scan still serves (no downtime yet);
2. the TLS Scan application (webui, api, worker, scheduler) is stopped, PostgreSQL alone keeps running, so that nothing
   is written between the backup and the copy; verified backup (`pg_dump -Fc` + data volume, SHA-256) and per-table row
   counts; PostgreSQL is then stopped too (containers kept, **volumes untouched**); `.env` is copied to `.env.pre-orion-<UTC>`;
3. `.env` gets `ORION_PROJECT=orion`, `ORION_DB_NAME=orion`, `ORION_DB_USER=orion`; new volumes `orion_pgdata` and
   `orion_data` are created and PostgreSQL initialised with the **same** protected password files;
4. the dump is restored as role `orion` (`--no-owner --no-privileges`) and the data volume copied;
5. the row counts of every table and the number of data entries must be identical **before Orion starts** (its scheduler may
   legitimately add rows afterwards); then Orion starts, migrations reach head and the five services are healthy.

A failure in step 2 restarts TLS Scan unchanged. Any failure from step 3 on stops Orion, restores `.env` byte for byte and restarts TLS Scan; the Orion volumes are kept for
analysis. The command refuses to run if an `orion` project already exists. Expect a service interruption from step 2 to the
end (backup + restore time, no image build); run it in a maintenance window.

```bash
./bootstrap_orion-deployment.sh backup                  # your own backup first, kept outside the host
./bootstrap_orion-deployment.sh migrate-orion           # typed confirmation: MIGRER VERS ORION
./bootstrap_orion-deployment.sh rollback-orion          # if needed: back to TLS Scan (typed RETOUR TLS SCAN)
```

`rollback-orion` stops Orion (volumes kept), puts back the latest `.env.pre-orion-*` copy and restarts the TLS Scan project.
Changes made in Orion since the migration are **not** carried back. `ORION_MIGRATION_PROJECT` overrides the target project
name, for a rehearsal on a host that already runs another installation.

Once Orion has been accepted, the TLS Scan volumes can be removed **manually**, after a last verified backup:
`docker volume rm tls-scan_pgdata tls-scan_data` (no command of the bootstrap does it). Until then `rollback-orion` works.

A backup archive of a TLS Scan installation can also be restored into a new Orion installation with the usual `restore`
command: objects are recreated under the `orion` role, and the API applies the pending migrations at start.

## External switchover (owner-coordinated)

These operations change identities outside the repository. They were executed with the owner's authorization on
20/11/2026, in this order, each with its rollback:

| # | Operation | Status (20/11/2026) | Rollback |
|---|---|---|---|
| 1 | Merge the rebranding into `_SANDBOX` (PR #52, #53, #54) | done: `_SANDBOX` = `c466b2a`; promotion to `_EXPERIMENT` → `main` follows the usual one-step PRs | revert PR |
| 2 | Integration VM: `update` the deployed stack in place (names pinned, verified backup) | done with the former script name; database at `0024`, row counts unchanged | restore the backup with the previous code (`releases/code-before-orion-*.tar.gz`) |
| 3 | Integration VM: `migrate-orion` | done: project, database and role `orion`; 47 tables and 198 data entries identical; `tls-scan_*` volumes kept | `rollback-orion` |
| 4 | GitHub repository `LCIT-CyberSecurity/Scan_TLS` → `LCIT-CyberSecurity/Orion` | done: same id (779231149), PRs, history and branch ruleset kept; old URLs redirect (web, API, git) | rename back (redirects follow) |
| 5 | CI: `orion.py` in the `compileall` step of `.github/workflows/ci.yml` | done in this change | revert |
| 6 | Jira project *LCIT Scan TLS* → *Orion* (display name only, key `LST` kept) | **manual**: Project settings → Details → Name; not available through the automation API | rename back |
| 7 | n8n / runner: multi-project registry, allowlist, WF-08 notifications | verified unchanged: they use the stable identifier `LCIT-CyberSecurity/Scan_TLS` and the repository id, both still resolved by GitHub (checked from the runner). Renaming that identifier requires a coordinated registry + WF-08 + runner image change in the automation platform | n/a |
| 8 | Integration VM directories: deployment `/home/cdev/tls-scan` → `/home/cdev/orion`, development sync `/home/cdev/tlsscan-dev` → `/home/cdev/orion-dev` | done, each former path kept as a symbolic link; `VM_DEST` defaults updated in this change | move back, remove the links |
| 9 | After acceptance: remove the `tls-scan_*` volumes and the rehearsal `lst29*` volumes; later major version: remove the aliases | owner decision; last verified backup first | restore the backup |

## Verification references

* Automated: `tests/bootstrap/run.sh` (recognition of existing installations, no empty volume, pins, `migrate-config`,
  `migrate-orion` success / automatic rollback / refusal, `rollback-orion`, former script name), `tests/backend/test_orion_identity.py`
  (legacy variables and priority, package alias, former CLI, Compose fallbacks, migration `0024` up/down/idempotent, legacy session
  cookie), `tests/backend/test_external_access.py` (legacy API/MCP keys and MCP tool aliases), frontend `shell-navigation` test
  (legacy local preferences).
* Rehearsal on an isolated clone (real Docker, real PostgreSQL): see the evidence recorded in Jira LST-29.
