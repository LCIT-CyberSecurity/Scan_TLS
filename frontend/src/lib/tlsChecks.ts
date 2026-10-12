/** Helpers for the `checks.tls` section of a scan profile (complementary TLS checks). Pure functions, no React. */
export interface TlsCheckSpec { id: string; family: string; recommended: boolean }
export type TlsSection = Record<string, unknown>;
export type TlsCheckStatus = "PASS" | "FAIL" | "NOT_TESTED" | "NOT_APPLICABLE" | "INCONCLUSIVE" | "ERROR";
export interface TlsCheckResult { check_id: string; status: TlsCheckStatus; message: string; observations?: Record<string, unknown>; evidence?: string[]; duration_ms?: number | null }

/** A check is enabled only when explicitly so: a profile without the section keeps the historical behaviour. */
export function isEnabled(section: TlsSection | undefined, id: string): boolean {
  const entry = section?.[id];
  if (typeof entry === "boolean") return entry;
  return !!entry && typeof entry === "object" && (entry as { enabled?: unknown }).enabled === true;
}

export function setEnabled(section: TlsSection | undefined, id: string, enabled: boolean): TlsSection {
  const next = { ...(section ?? {}) };
  if (enabled) next[id] = { enabled: true };
  else delete next[id];
  return next;
}

/** Selection pre-filled for NEW profiles only. */
export function recommendedSection(catalog: TlsCheckSpec[]): TlsSection {
  return Object.fromEntries(catalog.filter((c) => c.recommended).map((c) => [c.id, { enabled: true }]));
}

/** Shown by default: recommended checks, the ones already enabled and the ones the user added. */
export function visibleChecks(catalog: TlsCheckSpec[], section: TlsSection | undefined, added: string[]): TlsCheckSpec[] {
  return catalog.filter((c) => c.recommended || isEnabled(section, c.id) || added.includes(c.id));
}

export function groupByFamily(checks: TlsCheckSpec[]): [string, TlsCheckSpec[]][] {
  const groups = new Map<string, TlsCheckSpec[]>();
  for (const c of checks) groups.set(c.family, [...(groups.get(c.family) ?? []), c]);
  return [...groups.entries()];
}

/** Writes `checks.tls` without touching the other `checks` sections; an empty section is removed. */
export function withTlsSection(content: Record<string, unknown>, section: TlsSection): Record<string, unknown> {
  const checks = { ...((content.checks as Record<string, unknown>) ?? {}) };
  if (Object.keys(section).length) checks.tls = section;
  else delete checks.tls;
  return { ...content, checks };
}
