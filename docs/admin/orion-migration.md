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
audit events) and administrator-entered values that mention the former name. The Git repository `Scan_TLS`, the Jira project
name and the integration VM paths change only with the external switchover below.

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

1. verified backup of the TLS Scan installation (`pg_dump -Fc` + data volume, SHA-256) and per-table row counts;
2. TLS Scan is stopped (containers kept, **volumes untouched**); `.env` is copied to `.env.pre-orion-<UTC>`;
3. `.env` gets `ORION_PROJECT=orion`, `ORION_DB_NAME=orion`, `ORION_DB_USER=orion`; the images are built; new volumes
   `orion_pgdata` and `orion_data` are created and PostgreSQL initialised with the **same** protected password files;
4. the dump is restored as role `orion` (`--no-owner --no-privileges`) and the data volume copied;
5. the row counts of every table and the number of data entries must be identical **before Orion starts** (its scheduler may
   legitimately add rows afterwards); then Orion starts, migrations reach head and the five services are healthy.

Any failure from step 3 on stops Orion, restores `.env` byte for byte and restarts TLS Scan; the Orion volumes are kept for
analysis. The command refuses to run if an `orion` project already exists. Expect a service interruption from step 2 to the
end (backup + restore time); run it in a maintenance window.

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

## External switchover (owner-coordinated, not automated)

These operations change identities outside the repository. They are prepared here and executed only with the owner, in this
order, each with its rollback:

| # | Operation | Preparation / verification | Rollback |
|---|---|---|---|
| 1 | Merge the rebranding through `_SANDBOX` → `_EXPERIMENT` → `_UNSTABLE` → `_TESTING` → `main` | one PR per stage, as for any change | revert PR |
| 2 | Integration VM: `update` the `tls-scan` stack from `/home/cdev/tlsscan-dev` (in-place upgrade, names pinned) | backup first; check health, sign-in, a scan | restore the backup with the previous image tag |
| 3 | Integration VM: `migrate-orion` (maintenance window) | rehearsed on an isolated clone (see Jira LST-29) | `rollback-orion` |
| 4 | Rename the GitHub repository `LCIT-CyberSecurity/Scan_TLS` → `LCIT-CyberSecurity/Orion` | GitHub keeps redirects for clones, PRs and links; update `git remote set-url` on the VM and workstations, `ops/dev/vm.sh` / `tests/regression/run.sh` defaults if the VM directory is renamed, branch protections, GitHub App installation, Actions secrets/variables, badges | rename back (redirects follow) |
| 5 | Optionally add `orion.py` to the `compileall` step of `.github/workflows/ci.yml` (it already passes: `tls_scan.py` is kept) | CI change: owner approval | revert |
| 6 | Rename the Jira project *LCIT Scan TLS* → *Orion* (display name only) | the key `LST` and every `LST-n`, history, links and PR references stay | rename back |
| 7 | n8n: multi-project registry, allowlist, credentials, notifications, repository name | update after step 4; test a dry run without triggering a wave | previous workflow version |
| 8 | Integration VM directory `/home/cdev/tlsscan-dev` → e.g. `/home/cdev/orion` | only together with the default `VM_DEST` of `ops/dev/vm.sh` and `tests/regression/run.sh`, after checking `rsync --delete` targets | move back |
| 9 | After acceptance: remove the TLS Scan volumes; later major version: remove the aliases | last verified backup; announcement | restore the backup |

## Verification references

* Automated: `tests/bootstrap/run.sh` (recognition of existing installations, no empty volume, pins, `migrate-config`,
  `migrate-orion` success / automatic rollback / refusal, `rollback-orion`, former script name), `tests/backend/test_orion_identity.py`
  (legacy variables and priority, package alias, former CLI, Compose fallbacks, migration `0024` up/down/idempotent, legacy session
  cookie), `tests/backend/test_external_access.py` (legacy API/MCP keys and MCP tool aliases), frontend `shell-navigation` test
  (legacy local preferences).
* Rehearsal on an isolated clone (real Docker, real PostgreSQL): see the evidence recorded in Jira LST-29.
