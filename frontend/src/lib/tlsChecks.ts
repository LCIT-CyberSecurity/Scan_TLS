/** Helpers for the `checks.tls` section of a scan profile (complementary TLS checks). Pure functions, no React. */
export interface TlsOptionSpec { name: string; kind: "int" | "bool" | "ports"; default: unknown; min: number | null; max: number | null }
export interface TlsCheckSpec { id: string; family: string; recommended: boolean; options?: TlsOptionSpec[] }
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

/** Value of a technical option of an enabled check, or `undefined` when the profile does not set it (the engine default applies). */
export function getOption(section: TlsSection | undefined, id: string, name: string): unknown {
  const entry = section?.[id];
  return entry && typeof entry === "object" ? (entry as Record<string, unknown>)[name] : undefined;
}

/** Sets (or, with `undefined`, removes) an option of a check; the check stays enabled and a boolean shorthand becomes a mapping. */
export function setOption(section: TlsSection | undefined, id: string, name: string, value: unknown): TlsSection {
  const current = section?.[id];
  const entry: Record<string, unknown> = current && typeof current === "object" ? { ...(current as Record<string, unknown>) } : { enabled: current === true };
  if (value === undefined) delete entry[name];
  else entry[name] = value;
  return { ...(section ?? {}), [id]: entry };
}

/** "143, 1143" -> [143, 1143]; empty -> undefined (standard ports); invalid, duplicated or too many ports -> null. */
export function parsePorts(text: string): number[] | undefined | null {
  const parts = text.split(/[\s,;]+/).filter(Boolean);
  if (!parts.length) return undefined;
  const ports = parts.map((p) => (/^\d{1,5}$/.test(p) ? Number(p) : NaN));
  if (ports.some((p) => !(p >= 1 && p <= 65535)) || new Set(ports).size !== ports.length || ports.length > 16) return null;
  return ports;
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
