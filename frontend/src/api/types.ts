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
export interface Definition { id: string; name: string; description: string; owner_id: string | null; profile_id: string; report_template_id: string | null; policy_mode: string; tags: string[]; si_ids: string[]; target_ids: string[]; group_ids: string[]; policy_ids: string[]; exclusions?: string[] }
export type RunStatus = "scheduled" | "queued" | "running" | "completed" | "partial" | "failed" | "cancelled" | "expired";
export interface RunSummary { total_endpoints?: number; compliant_endpoints?: number; non_compliant_endpoints?: number; critical_findings?: number; high_findings?: number; overall_grade?: string; endpoints_with_errors?: number; checks_not_tested?: number }
export interface Run { id: string; name: string; definition_id: string | null; schedule_id: string | null; initiated_by: string | null; status: RunStatus; phase: string; queued_at: string; started_at: string | null; finished_at: string | null; duration_seconds: number | null; cancel_requested: boolean; error: string; progress: { hosts_total: number; hosts_done: number } | null; summary: RunSummary | null; policy_versions: { name: string; version: number }[]; reports: { format: string; size: number }[]; skipped_hosts?: string[]; config_snapshot?: Record<string, unknown>; plan?: RunPlan | null; exclusions?: RunExclusions | null }
export interface TrustStoreResult { store_id: string; store_name: string; store_type: string; status: string; validation_error?: string; trust_anchor_subject?: string }
export type TrustClass = "PUBLIC_TRUSTED" | "PRIVATE_TRUSTED" | "UNTRUSTED" | "NOT_TESTED" | "ERROR";
export interface CertificateInfo {
  [key: string]: string | number | string[] | TrustStoreResult[] | null | undefined;
  trust_classification?: TrustClass | null; trusted_by?: string[] | null; trust_anchor?: string | null; trust_store_results?: TrustStoreResult[] | null;
}
export interface RunTrustStore { id: string; name: string; version: number; content_sha256: string; anchors: string[]; intermediate_count: number }
export interface Endpoint { endpoint_id: string; hostname: string; ip_address: string; port: string; grade: string; compliance_status: string; highest_severity: string; tls_versions: string[]; certificate: CertificateInfo; errors: string[]; untested_checks: string[]; tls_checks?: TlsCheckResult[]; tags?: string[] }
export interface Finding { finding_id: string; title: string; severity: string; status: string; category: string; evidence: string; remediation: string; affected_endpoint_ids: string[] }
export interface RunDetail extends Run { endpoints: Endpoint[]; findings: Finding[]; trust_stores?: RunTrustStore[] }
export interface Schedule { id: string; definition_id: string; owner_id: string | null; kind: string; params: Record<string, unknown>; timezone: string; active: boolean; next_run_at: string | null; last_run_at: string | null; last_run: { id: string; status: string; duration_seconds: number | null } | null; triggers?: { due_at: string; outcome: string; reason: string; run_id: string | null }[] }
export interface Comparison { old_run_id: string; new_run_id: string; warnings: string[]; new: FindingBrief[]; fixed: FindingBrief[]; persistent: FindingBrief[]; not_retested: FindingBrief[]; endpoints_added: string[]; endpoints_removed: string[]; endpoint_changes: Record<string, unknown>[]; counts: Record<string, number> }
export interface FindingBrief { finding_id: string; title: string; severity: string; affected: string[] }
export interface Posture {
  scans: number; basis_run_ids: string[]; policies: { name: string; version: number }[]; mixed_policies: boolean; window_days: number;
  endpoints: { total: number; compliant: number; non_compliant: number; unevaluated: number; rate: number | null };
  findings: { critical: { unique: number; endpoints: number }; high: { unique: number; endpoints: number }; occurrences: number };
  certificates: { expired: number; expiring: number; items: { subject: string; valid_until: string | null; remaining_days: number; endpoints: number; run_id: string }[] };
  vigilance: { finding_id: string; title: string; category: string; severity: string | null; endpoints: number; run_id: string | null }[];
}
export interface TrendPoint { run_id: string; name: string; finished_at: string; rate: number | null; compliant: number; non_compliant: number; evaluated: number; total: number; comparable: boolean }
export interface Trend { definition_id: string | null; definitions: { id: string; name: string; runs: number }[]; points: TrendPoint[] }
export interface Dashboard { counts: Record<string, number>; posture?: Posture; trend?: Trend; evolution?: Evolution; recent: Run[]; compliance_trend: { run_id: string; name: string; finished_at: string; compliant: number; non_compliant: number }[]; upcoming: Schedule[] }
export interface EvolutionRun { run_id: string; name: string; finished_at: string; endpoints: number; compliant: number; non_compliant: number; rate: number | null; findings: Record<"critical" | "high" | "medium" | "low", number> }
export interface EvolutionFinding { finding_id: string; title: string; severity: string; endpoints: number }
export interface Evolution { definition_id: string | null; date_from: string; date_to: string; status: "ok" | "single_run" | "no_runs" | "invalid_range";
  from_run: EvolutionRun | null; to_run: EvolutionRun | null; series: EvolutionRun[];
  comparison: { counts: { new: number; fixed: number; persistent: number; not_retested: number }; warnings: string[]; new: EvolutionFinding[]; fixed: EvolutionFinding[]; persistent: EvolutionFinding[];
    endpoints_added: number; endpoints_removed: number; certificate_changes: { endpoint_id: string; before: string | null; after: string | null }[]; compliance: { improved: number; degraded: number } } | null }
export interface Tag { id: string; name: string; color: string }

export interface TrustCert {
  fingerprint_sha256: string; role: "anchor" | "intermediate"; subject: string; issuer: string; serial: string; not_before: string; not_after: string;
  key_type: string; key_size: number | null; signature_algorithm: string; basic_constraints: { ca: boolean; path_length: number | null } | null; key_usage: string[] | null;
  expired: boolean; expires_in_days: number;
}
export interface TrustStoreSummary {
  id: string; name: string; description: string; builtin: boolean; type: "public" | "private"; active: boolean; version: number | null;
  certificate_count: number; anchor_count: number | null; has_expired: boolean; updated_at: string | null;
}
export interface TrustVersion { id: string; version: number; content_sha256: string; comment: string; created_at: string; anchor_count: number; intermediate_count: number; certificates?: TrustCert[] }
export interface TrustStoreDetail extends TrustStoreSummary { versions: TrustVersion[]; certificates: TrustCert[]; profiles: { id: string; name: string; versions: number[] }[]; run_count: number; content_sha256: string | null }
export interface TrustInspect { valid: boolean; files: { filename: string; error: string | null; certificates: (Omit<TrustCert, "expired" | "expires_in_days"> & { role: "anchor" | "intermediate" | null; error: string | null; duplicate: boolean })[] }[] }

export type DdInventory = "NEW" | "EXISTING" | "ENRICHABLE" | "CHANGED" | "OUT_OF_SCOPE";
export interface DdMethod { status: string; detail: string; found: number }
export interface DdJob { id: string; domain: string; status: "queued" | "running" | "done" | "failed"; error: string; cancel_requested: boolean; options: Record<string, unknown> | null;
  progress: { phase?: string; done?: number; total?: number; names?: number; queries?: number; methods?: Record<string, DdMethod> } | null }
export interface DdCoverage { covered: boolean; definitions: { id: string; name: string; via: "target" | "group" | "address"; group: string; scheduled: boolean }[]; definitions_total: number;
  shared_address: string[]; recently_scanned: boolean; last_scan: { run_id: string; name: string; finished_at: string | null } | null }
export interface DdItem { fqdn: string; in_scope: boolean; types: string[]; ips: string[]; cnames: string[]; sources: string[]; roles: string[]; resolved: boolean | null; wildcard: boolean; notes: string[];
  inventory: DdInventory; coverage: DdCoverage; matches: { id: string; ports: string; name: string; status: string }[]; ambiguous: boolean; diff: { new_ips: string[]; missing_ips: string[]; new_cnames: string[]; new_sources: string[]; cname_changed: boolean } | null }
export interface DdResults { total: number; counts: Record<string, number>; sources: Record<string, number>; items: DdItem[]; methods: Record<string, DdMethod>; nameservers: { name: string; address: string; status: string; records: number; source: string }[];
  security: { kind: string; server: string; address: string; message: string }[]; transfer_possible: boolean; truncated: boolean; partial: boolean; resolver: string;
  recent_scan_days: number; covered: number; recently_scanned: number }
export interface DdConfig { allowed_servers: string[]; ct_enabled: boolean; limits: { max_apply_items: number } }
export interface DdApplyItem { fqdn: string; outcome: "create" | "reuse" | "enrich" | "skip"; reason: string; target_id: string | null; candidates?: { id: string; ports: string }[]; classification?: string;
  dns?: { new_ips: string[]; missing_ips: string[] }; business_changes?: { tags_added: string[]; si_added: string[]; group_added: boolean } }
export interface DdReport { dry_run: boolean; applied: boolean; summary: { create: number; reuse: number; enrich: number; skipped: number; business_changes_pending_confirmation: number; classification_applied?: number }; group: { id: string | null; name: string; will_create?: boolean; created?: boolean } | null;
  definitions?: { id: string | null; name: string; action: "add_group" | "already" | "create"; scheduled: boolean }[]; items: DdApplyItem[] }

export interface RunPlan { targets: number; ports: string[]; crypto: string; certificate: boolean; trust: boolean; public_store: boolean; private_stores: string[]; revocation: boolean; tls_checks: number; policies: string[]; formats: string[] }
export interface DdSummary { id: string; domain: string; status: "queued" | "running" | "done" | "failed"; error: string; created_at: string; finished_at: string | null; mode: string; resolver: string;
  methods: Record<string, string>; names: number; in_scope: number; transfer_possible: boolean; partial: boolean; requested_by: string }
export interface RunExclusions { entries: { value: string; scope: "global" | "definition" | "profile" }[]; removed_targets: string[]; partial_targets: string[] }
