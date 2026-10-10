# Scope, limitations and V2

## Implemented and verified (see [tests](dev/testing.md))
Local admin with generated one-time password; local users; OIDC SSO (mock-tested); four global roles enforced
server-side; targets (FQDN/IP/CIDR, ports, ranges), groups, SI/sub-SI, tags, import/export; versioned policies and
profiles, YAML policy import/export; report templates (formats); scan definitions; manual and scheduled runs;
dedicated worker with process isolation, cancellation with partial results, timeouts, crash recovery; run
de-duplication under concurrency; comparison; reports (HTML/MD/CSV/CBOM/metadata) with integrity check; SMTP
notifications with diagnostics; audit log; retention; dashboard; "My tasks"; FR/EN/DE; light/dark/system + palettes;
bootstrap (install/update/backup/restore/reset-admin/uninstall); CrashTest; Playwright E2E.

## Not implemented / partial (be aware before relying on it)
* **Real Entra ID** not tested (mock OIDC only). **No directory connectors** (LDAP/AD, Google Workspace, Entra
  Graph): the authentication provider is separated from a directory abstraction only in the sense that SSO does
  not read directories; there is no connector framework or diagnostic page for them.
* **Microsoft Graph mail** not implemented (SMTP only). "New non-compliance", "certificate near expiry" and
  "schedule problem" notifications are not generated (only scan completed/failed/cancelled).
* **Report templates** choose formats only (no logo/colours/language/sections/detail level: the generators do not
  support them). Rapport language follows the engine (English).
* **PQC profile** is accepted but untested here (needs OpenSSL ≥ 3.5 in the image).
* **Custom trust stores** (corporate PKI files) are refused in WebUI profiles (they reference server file paths).
* Policy mode is `strict_all` only (the engine's only mode). The scan "progress" is hosts processed when the engine
  can tell, otherwise the phase.
* The login throttle and API rate limits are in-process (single API process). Not clustered; one worker host.
* No automatic clean-up of `schedule_triggers` and notification rows beyond run deletion cascades.
* The WebUI does not edit the Standalone YAML configuration; there is no CLI-to-WebUI connection (not in V1).
* Playwright E2E is run manually against the CrashTest; there is no CI pipeline yet. Frontend component tests are
  limited to i18n and the API client.
* Licence: this repository has no LICENSE file, while code and design tokens were adapted from LCIT-Sign
  (GPL-3.0): `auth/passwords.py`, `auth/oidc.py`, `frontend/src/styles/tokens.css`, the logos. Decide the licence of
  Scan_TLS before publishing a release (GPL-3.0 is compatible).

## Engine changes (the only modifications to `tls_scanner/`)
1. `tls_scanner/runner.py` (new): headless `execute_scan`, `collect_job_results`, `validate_scan_input`.
2. `tls_scanner/cli.py`: `run_job` calls `collect_job_results` for the discovery/scan/grade block (same output text).
3. `tls_scanner/scanner.py`: `scan_tls_hosts_parallel` accepts optional `cancel_event` and `on_host_done`
   (defaults: unchanged behaviour).
Evidence of compatibility: the 115 legacy tests pass, and `tests/regression/run.sh` shows CSV, findings CSV, CBOM,
Markdown, HTML and metadata **identical** to the baseline commit on the lab.

## V2 candidates
Re-evaluating past results with a new policy; directory connectors and Entra Graph; Graph mail; richer report
templates; certificate-expiry and new-non-compliance alerts; CLI ↔ WebUI link; CI pipeline; clustered rate limits.
