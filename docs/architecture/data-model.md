# Data model (PostgreSQL)

Migrations: `backend/migrations/versions` (Alembic, applied automatically when the API container starts).

| Domain | Tables |
|---|---|
| Identity | `users` (one global `role`), `sessions` (token hash, CSRF token, revocation), `organization` (single row) |
| Classification | `information_systems` (`parent_id` = sub-SI, one level), `tags`, `resource_tags`, `resource_si` (polymorphic: target / group / definition) |
| Targets | `targets` (`value`+`ports` unique: one record per target, reused everywhere), `target_groups`, `target_group_members` |
| Policies & profiles | `policies` / `policy_versions`, `scan_profiles` / `scan_profile_versions` (`draft → published → archived`, immutable once published), `report_templates` |
| Definitions | `scan_definitions`, `definition_targets`, `definition_groups`, `definition_policies` |
| Schedules | `scan_schedules`, `schedule_triggers` (history: triggered / skipped_overlap / skipped_late / error) |
| Runs | `scan_runs` (status, phase, fingerprint, `config_snapshot`, policy versions, heartbeat, summary, report files + SHA-256), `scan_run_requesters`, `run_endpoints`, `run_findings` |
| Network map | `network_zones` (independent nested classification), `network_zone_systems`, `network_zone_targets`, `network_devices`, `network_links` (typed provenance and source; no auto-discovery) |
| External access | `users.api_access_enabled`, `users.mcp_access_enabled` (default false, migration `0005`), `access_tokens` (hashed keys, expiry, last use, revocation; one non-revoked key per user and service), `system_settings['external_access']` (global switches, default off) |
| Discovery | `dns_discoveries` (DNS discovery requests and their result; migration `0004`) |
| Operations | `audit_events` (no FK to users: audit outlives accounts), `system_settings` (retention, SMTP), `notifications` (queue + delivery status) |

`run_endpoints.tls_checks` (JSON, nullable, migration `0006`) keeps the results of the complementary TLS checks of an endpoint
(`check_id`, `status`, `message`, `observations`, `evidence`, `duration_ms`). Rows stored before the migration have no value and are
never requalified; the scan fingerprint already includes `checks`, so enabling a check never de-duplicates onto a run made without it.

Run results mirror the engine's `ReportModel` (`tls_scanner/exports/report_model.py`): `run_endpoints` keeps
grade, compliance, TLS versions, cipher suite names, certificate summary, errors and *untested checks*;
`run_findings` keeps id, severity, evidence, remediation and affected endpoints. The full engine model is also
embedded in the generated reports.
