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

## Backup / restore
`./bootstrap_tls-scan-deployment.sh backup [dir]` writes one verified archive (`db.dump`, `data.tar` = reports and logs,
`SHA256SUMS`, `MANIFEST.txt`; default `./backups`, mode 600). `restore <archive>` re-checks the sums and the dump,
takes a safety backup, and replaces the data only after the typed confirmation (`RESTAURER`); a corrupted archive is refused
before anything is modified. `update`, `reinstall` and `uninstall` offer a backup first and stop if it fails.
Keep `.env` and `data/certs` in your own secret backup (not in the archive). Restoring on a fresh host: `install`, then
`restore <file>`. Details: [installation](install.md).
