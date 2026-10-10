# Scope, limitations and V2

## Implemented and verified (see [tests](dev/testing.md))
Local admin with the default password `SecretPassword` (change forced at first sign-in); local users; OIDC SSO (mock-tested); LDAP and Entra directory lookup with pre-provisioning; four global roles enforced
server-side; targets (FQDN/IP/CIDR, ports, ranges), groups, SI/sub-SI, tags, import/export; versioned policies and
profiles, YAML policy import/export; report templates (formats); scan definitions; manual and scheduled runs;
dedicated worker with process isolation, cancellation with partial results, timeouts, crash recovery; run
de-duplication under concurrency; comparison; reports (HTML/MD/CSV/CBOM/metadata) with integrity check; SMTP and Microsoft Graph
notifications with diagnostics and the five event types; HTML report branding; audit log; retention; dashboard; "My tasks"; FR/EN/DE; light/dark/system + palettes;
bootstrap (install/update/backup/restore/reset-admin/uninstall); CrashTest; Playwright E2E.

## Not implemented / partial (be aware before relying on it)
* **Real Entra ID is not tested** (SSO: mock OIDC only; directory and Graph mail: mock Graph server only). The code follows the
  documented protocols; expect to adjust claims/permissions on a real tenant. LDAP **is** tested against a real OpenLDAP.
* **Google Workspace** connector: not implemented. Group-based directory sync: not implemented (not needed: no per-SI access control).
* **Report templates** apply to the **HTML** report only: organisation name on the cover, accent colour, logo (validated data
  URI) and the export formats. Report **language** and **sections / detail level** are those of the engine (English; not
  configurable) because the generators do not support them.
* **Custom trust stores** (corporate PKI files) are refused in WebUI profiles (they reference server file paths).
* Policy mode is `strict_all` only (the engine's only mode). Scan "progress" is hosts processed when the engine can tell,
  otherwise the phase.
* The login throttle is in-process (single API process, counts failed attempts). One worker host; no clustering.
* No automatic clean-up of `schedule_triggers` and notification rows beyond run-deletion cascades.
* The WebUI does not edit the Standalone YAML configuration; there is no CLI-to-WebUI link (not in V1).
* CI: `.github/workflows/ci.yml` runs the same commands as the integration VM but **has not been executed on GitHub's runners**.
* Licence: this repository has no LICENSE file, while code and design tokens were adapted from LCIT-Sign (GPL-3.0):
  `auth/passwords.py`, `auth/oidc.py`, `frontend/src/styles/tokens.css`, the logos. Decide the licence of Scan_TLS before
  publishing a release (GPL-3.0 is compatible).

## Engine changes (the only modifications to `tls_scanner/`)
1. `tls_scanner/runner.py` (new): headless `execute_scan`, `collect_job_results`, `validate_scan_input`.
2. `tls_scanner/cli.py`: `run_job` calls `collect_job_results` for the discovery/scan/grade block (same output text).
3. `tls_scanner/scanner.py`: `scan_tls_hosts_parallel` accepts optional `cancel_event` and `on_host_done`
   (defaults: unchanged behaviour).
Evidence of compatibility: the 115 legacy tests pass, and `tests/regression/run.sh` shows CSV, findings CSV, CBOM,
Markdown, HTML and metadata **identical** to the baseline commit on the lab.

## V2 candidates
Re-evaluating past results with a new policy; Google Workspace connector; tests against a real Entra tenant; report language and
section selection (needs engine support); CLI ↔ WebUI link; clustered rate limits.
