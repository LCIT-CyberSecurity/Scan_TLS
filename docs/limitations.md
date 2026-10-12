# Scope, limitations and V2

## Implemented and verified (see [tests](dev/testing.md))
Local admin with the default password `SecretPassword` (change forced at first sign-in); local users; OIDC SSO (mock-tested); LDAP and Entra directory lookup with pre-provisioning; four global roles enforced
server-side; targets (FQDN/IP/CIDR, ports, ranges), groups, SI/sub-SI, tags, import/export; versioned policies and
profiles, YAML policy import/export; report templates (formats); scan definitions; manual and scheduled runs;
dedicated worker with process isolation, cancellation with partial results, timeouts, crash recovery; run
de-duplication under concurrency; comparison; reports (HTML/MD/CSV/CBOM/metadata) with integrity check; SMTP and Microsoft Graph
notifications with diagnostics and the five event types; HTML report branding; audit log; retention; dashboard; "My tasks"; FR/EN/DE; light/dark/system + palettes;
bootstrap (Standalone / WebUI menu, install/update/backup/restore/reset-admin/reinstall/uninstall); read-only external REST API and MCP server with per-user keys; DNS discovery; CrashTest; Playwright E2E.

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

* **External API and MCP** (read-only, `docs/integrations`): one active key per user and service, 90-day validity, no scoped or write-capable keys, no per-SI visibility (roles are global, like the WebUI), in-process rate limits (single API process), no report download or scan launch through them. MCP is exercised with the official Python client only.
* **DNS discovery** is a zone-transfer attempt only (no brute force, no passive sources); most servers refuse it, which is the expected result. It runs in the worker and needs outbound DNS from it.

## Complementary TLS checks (lots 1 and 2)
Implemented and validated against the lab and OpenSSL: identity/SAN, OCSP stapling, ECDHE groups, FFDHE/DH parameters, compression,
renegotiation, FALLBACK_SCSV, Extended Master Secret, session resumption and tickets, TLS 1.3 early data, client authentication detection,
IMAP/POP3/LDAP/FTP/PostgreSQL/XMPP STARTTLS ([reference](user/tls-checks.md)). Known limits:
* **Not graded**: results are shown next to the findings; the historical grade, compliance status, CSV and CBOM are not modified. Taking them
  into the grade needs an explicit, tested decision (later lot).
* Group checks prove *accepted* groups with one-group offers; they are not a complete inventory (no legacy curves, no hybrid ML-KEM here).
* TLS 1.3-only servers: the stapled OCSP response is read from the decrypted Certificate message and fully verified; only if that transcript cannot be
  parsed does the text fallback apply (signature then not verified, and stated). Compression / renegotiation / EMS / SCSV are `NOT_APPLICABLE`.
* Raw-handshake checks (compression, renegotiation, SCSV, EMS, stapling on TLS ≤ 1.2) support direct TLS, SMTP and the opt-in STARTTLS protocols
  (only when the `starttls_*` check of the port is selected; otherwise the service is not speaking TLS and the result is `INCONCLUSIVE`). SSLv3 / TLS 1.0 specific probing is not done (SCSV may choose TLS 1.1 or 1.2 as the downgraded version).
* The client-initiated renegotiation test depends on `openssl s_client` behaviour and can be `undetermined`.
* An IP-literal target is checked against IP SAN entries and fails when there are none (reported as such).
* Session checks: a refusal after a few attempts is not proof that a server cannot resume (load-balanced back-ends); ticket-key rotation and strength are not
  observable from outside; a TLS 1.3 ticket not received within `ticket_wait_seconds` is `INCONCLUSIVE`.
* 0-RTT: acceptance is shown only by the optional deep probe, which sends an empty line as early data; it is skipped on STARTTLS channels. Accepted 0-RTT is
  information (replay exposure), never graded.
* mTLS: no client certificate is supported (nothing secret is read or stored). A completed handshake does not prove the application does not authenticate users;
  a failed one does not prove mTLS by itself.
* STARTTLS adapters speak the minimum dialogue. They are validated against scripted lab services and against Postfix, Dovecot, vsftpd, OpenLDAP, PostgreSQL and Prosody
  (`tests/regression/real-servers.sh`); other implementations (ejabberd, Exim, Cyrus, ProFTPD...) have not been tried. XMPP is covered on the client-to-server and server-to-server
  streams (no dialback). Which endpoints are scanned still comes from Nmap, which is the discovery engine and is not replaced: for non-standard ports use the `ports` option.
* Heartbleed, ROBOT, CCS injection and the decision to grade these results do not exist yet (lot 3) and are not offered anywhere.

## Engine changes (the only modifications to `tls_scanner/`)
1. `tls_scanner/runner.py` (new): headless `execute_scan`, `collect_job_results`, `validate_scan_input`.
2. `tls_scanner/cli.py`: `run_job` calls `collect_job_results` for the discovery/scan/grade block (same output text).
3. `tls_scanner/scanner.py`: `scan_tls_hosts_parallel` accepts optional `cancel_event` and `on_host_done`
   (defaults: unchanged behaviour).
4. Complementary TLS checks: new `tls_scanner/checks/*` modules; targeted hooks in `config.py` (`checks.tls`), `models.py` (new `ScanJob` fields,
   all defaulting to "none"), `scanner.py` (one conditional call), `runner.py` (requested names, only when `hostname_san` is selected),
   `exports/report_model.py` (`complementary_checks`, omitted when empty), the HTML and Markdown renderers (section only when present).
Evidence of compatibility: the 115 legacy tests pass, and `tests/regression/run.sh` shows CSV, findings CSV, CBOM,
Markdown, HTML and metadata **identical** to the baseline commit on the lab.

## V2 candidates
Re-evaluating past results with a new policy; Google Workspace connector; tests against a real Entra tenant; report language and
section selection (needs engine support); CLI ↔ WebUI link; clustered rate limits.
