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
| Operations | `audit_events` (no FK to users: audit outlives accounts), `system_settings` (retention, SMTP), `notifications` (queue + delivery status) |

Run results mirror the engine's `ReportModel` (`tls_scanner/exports/report_model.py`): `run_endpoints` keeps
grade, compliance, TLS versions, cipher suite names, certificate summary, errors and *untested checks*;
`run_findings` keeps id, severity, evidence, remediation and affected endpoints. The full engine model is also
embedded in the generated reports.
