import type { TlsCheckResult } from "../lib/tlsChecks";
export type Role = "AUDITOR" | "USER" | "OPERATOR" | "ADMIN";
export interface User { id: string; email: string; display_name: string; role: Role; must_change_password: boolean; locale: string | null; theme: string; palette: string; notify_events: string[] | null; local_account: boolean; active?: boolean; last_login_at?: string; api_access_enabled?: boolean; mcp_access_enabled?: boolean; access_keys?: Record<AccessService, AccessKey> }
export type AccessService = "api" | "mcp";
export interface AccessKey { active: boolean; prefix: string | null; created_at: string | null; expires_at: string | null; last_used_at: string | null }
export type MyAccess = Record<AccessService, { global_enabled: boolean; allowed: boolean; key: AccessKey }>
export interface SI { id: string; name: string; description: string; parent_id: string | null }
export interface Target { id: string; name: string; value: string; kind: string; ports: string; description: string; owner_id: string | null; tags: string[]; si_ids: string[] }
export interface Group { id: string; name: string; description: string; owner_id: string | null; target_ids: string[]; tags: string[]; si_ids: string[] }
export interface Version { id: string; version: number; status: "draft" | "published" | "archived"; content: Record<string, unknown>; published_at: string | null }
export interface Versioned { id: string; name: string; description: string; archived: boolean; versions: Version[] }
export interface Template { id: string; name: string; description: string; export_formats: string[]; organization_name: string; accent_color: string; has_logo: boolean; logo: string }
export interface Definition { id: string; name: string; description: string; owner_id: string | null; profile_id: string; report_template_id: string | null; policy_mode: string; tags: string[]; si_ids: string[]; target_ids: string[]; group_ids: string[]; policy_ids: string[] }
export type RunStatus = "scheduled" | "queued" | "running" | "completed" | "partial" | "failed" | "cancelled" | "expired";
export interface RunSummary { total_endpoints?: number; compliant_endpoints?: number; non_compliant_endpoints?: number; critical_findings?: number; high_findings?: number; overall_grade?: string; endpoints_with_errors?: number; checks_not_tested?: number }
export interface Run { id: string; name: string; definition_id: string | null; schedule_id: string | null; initiated_by: string | null; status: RunStatus; phase: string; queued_at: string; started_at: string | null; finished_at: string | null; duration_seconds: number | null; cancel_requested: boolean; error: string; progress: { hosts_total: number; hosts_done: number } | null; summary: RunSummary | null; policy_versions: { name: string; version: number }[]; reports: { format: string; size: number }[]; skipped_hosts?: string[]; config_snapshot?: Record<string, unknown> }
export interface Endpoint { endpoint_id: string; hostname: string; ip_address: string; port: string; grade: string; compliance_status: string; highest_severity: string; tls_versions: string[]; certificate: Record<string, string | number | null>; errors: string[]; untested_checks: string[]; tls_checks?: TlsCheckResult[]; tags?: string[] }
export interface Finding { finding_id: string; title: string; severity: string; status: string; category: string; evidence: string; remediation: string; affected_endpoint_ids: string[] }
export interface RunDetail extends Run { endpoints: Endpoint[]; findings: Finding[] }
export interface Schedule { id: string; definition_id: string; owner_id: string | null; kind: string; params: Record<string, unknown>; timezone: string; active: boolean; next_run_at: string | null; last_run_at: string | null; last_run: { id: string; status: string; duration_seconds: number | null } | null; triggers?: { due_at: string; outcome: string; reason: string; run_id: string | null }[] }
export interface Comparison { old_run_id: string; new_run_id: string; warnings: string[]; new: FindingBrief[]; fixed: FindingBrief[]; persistent: FindingBrief[]; not_retested: FindingBrief[]; endpoints_added: string[]; endpoints_removed: string[]; endpoint_changes: Record<string, unknown>[]; counts: Record<string, number> }
export interface FindingBrief { finding_id: string; title: string; severity: string; affected: string[] }
export interface Posture { scans: number; endpoints: number; compliant: number; non_compliant: number; critical: number; high: number; not_tested: number; grades: Record<string, number> }
export interface Dashboard { counts: Record<string, number>; posture?: Posture; recent: Run[]; compliance_trend: { run_id: string; name: string; finished_at: string; compliant: number; non_compliant: number }[]; upcoming: Schedule[] }
export interface Tag { id: string; name: string; color: string }
