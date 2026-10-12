# Operations: limits, logs, troubleshooting, retention

## Limits (`.env`)
`TLS_SCAN_MAX_CONCURRENT_SCANS`, `TLS_SCAN_MAX_SCAN_DURATION_SECONDS` (→ status *expired*, partial results kept),
`TLS_SCAN_MAX_TARGETS_PER_SCAN` (total addresses, CIDRs expanded), `TLS_SCAN_MAX_SCAN_WORKERS`. Container CPU/memory:
`TLS_SCAN_WORKER_CPUS`, `TLS_SCAN_WORKER_MEMORY`.

## Three kinds of traces
* **Audit** (*Administration → Audit log*): who did what — sign-ins (success/failure/blocked), role changes,
  policy/profile/target/definition/schedule changes, scan queued/started/cancelled/finished, report downloads,
  settings changes. Retention is separate (`audit_days`).
* **Technical logs**: `./bootstrap_tls-scan-deployment.sh logs [api|worker|scheduler]` (one JSON-free line per event,
  component name in each line, secrets scrubbed: `password|secret|token|cookie|authorization|api_key` values and
  URL credentials are masked). Per-scan engine log (nmap phases, PKI checks) with the `scan_run_id` correlation id:
  `/var/lib/tls-scan/logs/scans/<run id>.log`.
* **Troubleshooting views** (ADMIN): *Diagnostics* (database, nmap, openssl, SSO configured, free disk, active runs,
  limits) and *failed or partial scans* with the error; OPERATOR also has the failed-runs list.

## Why…?
| Symptom | Where to look |
|---|---|
| Scan fails | run page error + `failed-runs`; `worker` log; per-scan log. `worker lost` = the worker restarted mid-scan. |
| Scan does not start | still `queued`: global concurrency cap reached (Diagnostics → active runs), or worker down (`status`). |
| Schedule ignored | *Schedules → History*: `skipped_overlap` (previous run still active / merged into an equivalent run), `skipped_late` (service was down > 15 min), `error` (e.g. policy has no published version). |
| Report missing | run has no `reports`: engine failed before export; with a download 500 *integrity check failed* the file changed on disk (audit event `report.integrity_failure`). |
| SSO fails | audit `auth.sso_login` failure (`reason`, scrubbed detail) + `api` log; check issuer, client id/secret, redirect URI = `<PUBLIC_BASE_URL>/api/auth/sso/callback`. |
| No e-mail | *Administration → Settings → SMTP → Test connection* (DNS, TLS certificate, authentication, send, each with a readable explanation); delivery log at `/api/admin/notifications`. |

## Retention
*Administration → Settings*: report files (days), run history (days), audit log (days). The worker purges hourly
and records `retention.purge` in the audit log. Deleting a run (OPERATOR) also removes its report files.

## Complementary TLS checks

They add connections to each endpoint of a profile that enables them: 1–3 for most checks, up to about 18 for `ecdhe_groups` and 7
for `ffdhe_groups`, up to about 10 for the shared session probes, 2–4 for 0-RTT and client authentication, 1 per STARTTLS protocol check (only on its ports), each bounded by `timeout_seconds` and by a per-endpoint `time_budget_seconds` (defaults 10 s / 120 s, YAML
`checks.tls`), inside the worker that scans the host (`scan.workers` limits concurrency as before). Consider `TLS_SCAN_MAX_SCAN_DURATION_SECONDS`
if you enable them on large ranges. They need `openssl` in the worker image (already present). A failing check
is logged and stored as `ERROR` without failing the run. Nothing sensitive is stored: results hold observations and short evidence
lines (never keys or raw captures). Disabling them in the profile restores the previous behaviour; stored results stay as they were.

## External API and MCP access

Two read-only services, **both off by default** and independent of each other (details: [external API](../integrations/external-api.md), [MCP](../integrations/mcp.md)).

1. **Enable a service** — *Administration → Settings → External access*: switch **External API** (`/api/v1`) and/or **MCP server** (`/mcp`). Stored in PostgreSQL (`system_settings`), applied immediately without restart, audited. Switching a service **off** refuses every key at once (they are *suspended*, not revoked: switching it on again re-activates the keys that are still valid, authorised and not revoked); no new key can be generated while it is off; keys can still be revoked.
2. **Authorise users** — *Administration → Users*: tick **API** and/or **MCP** per user (off for everyone, administrators included, until you do). Withdrawing the authorisation, deactivating the user or deleting the account **revokes the keys immediately**; a role change applies to the existing key immediately. You cannot create a key for someone else nor read it: owners generate their own in *Preferences → API and MCP access*; you can **revoke** any key (*Revoke* in the Users table).
3. **Keys** — `tls_scan_pat_…` (REST) and `tls_scan_mcp_…` (MCP), SHA-256 only in the database, 90 days, one active key per user and service, never logged. They are not part of backups in clear: the `access_tokens` table (hashes) is in the PostgreSQL dump, secrets are not recoverable by design.
4. **HTTPS and reverse proxy** — the bundled nginx terminates TLS and forwards `/api/*` and `/mcp` (streaming, no buffering, 64 KB body). Behind another proxy: forward `/mcp` to the API without buffering, keep the `Host` header, and set `TLS_SCAN_PUBLIC_BASE_URL` (its host is allowed for MCP; add others with `TLS_SCAN_MCP_ALLOWED_HOSTS` / `TLS_SCAN_MCP_ALLOWED_ORIGINS`). Do not expose the API over plain HTTP.
5. **Controls in place** — rate limits (REST 120 req/min per key; MCP 240 requests and 60 tool calls/min per key), Host/Origin validation, bounded pages, 25 s tool timeout, read-only handlers with explicit output schemas, uniform `401` for every authentication failure.
6. **Audit and supervision** — *Administration → Audit log*, filter by action: `external_access.` (switches, authorisations, key created / refused / revoked), `external_api.` (`auth_failed`, `rate_limited`, scan reads), `mcp.` (`tool_called`, `tool_denied`, `auth_failed`, `rate_limited`). Failures are throttled per source address. Events follow the audit retention.
7. **Incidents** — a leaked key: revoke it (owner or administrator) or switch the service off; check `external_api.auth_failed` / `mcp.auth_failed` for repeated reasons (`unknown key`, `expired`, `not authorised`). A user who reports `401`: check the service switch, their authorisation, the key expiry and that their account is active and has changed its initial password.
8. **Backup** — the settings (`system_settings`), the per-user flags and the key hashes are in the PostgreSQL part of `backup`; restoring a backup restores them (users whose key was created after the backup lose it and must generate a new one).

## Backup / restore
`./bootstrap_tls-scan-deployment.sh backup [dir]` writes one verified archive (`db.dump`, `data.tar` = reports and logs,
`SHA256SUMS`, `MANIFEST.txt`; default `./backups`, mode 600). `restore <archive>` re-checks the sums and the dump,
takes a safety backup, and replaces the data only after the typed confirmation (`RESTAURER`); a corrupted archive is refused
before anything is modified. `update`, `reinstall` and `uninstall` offer a backup first and stop if it fails.
Keep `.env` and `data/certs` in your own secret backup (not in the archive). Restoring on a fresh host: `install`, then
`restore <file>`. Details: [installation](install.md).
