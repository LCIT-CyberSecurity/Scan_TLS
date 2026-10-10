// Thin fetch wrapper: cookie session + CSRF header on state-changing requests.
let csrfToken = "";
export const setCsrf = (token: string) => { csrfToken = token; };

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

function detailToMessage(detail: unknown): string {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) return detail.map((d) => (d?.msg ? `${(d.loc ?? []).slice(1).join(".")}: ${d.msg}` : String(d))).join("; ");
  return "Request failed";
}

export async function api<T = unknown>(path: string, options: { method?: string; body?: unknown; params?: Record<string, string | boolean | undefined> } = {}): Promise<T> {
  const method = options.method ?? "GET";
  const query = options.params
    ? "?" + new URLSearchParams(Object.entries(options.params).filter(([, v]) => v !== undefined && v !== "" && v !== false).map(([k, v]) => [k, String(v)]))
    : "";
  const response = await fetch(`/api${path}${query === "?" ? "" : query}`, {
    method,
    credentials: "same-origin",
    headers: { ...(options.body !== undefined ? { "Content-Type": "application/json" } : {}), ...(method !== "GET" ? { "X-CSRF-Token": csrfToken } : {}) },
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
  });
  if (response.status === 204) return undefined as T;
  const text = await response.text();
  let data: unknown = undefined;
  try { data = text ? JSON.parse(text) : undefined; } catch { data = text; }
  if (!response.ok) {
    if (response.status === 401) window.dispatchEvent(new Event("tls-scan:unauthorized"));
    throw new ApiError(response.status, detailToMessage((data as { detail?: unknown })?.detail ?? data));
  }
  return data as T;
}

export const downloadUrl = (runId: string, format: string, inline = false) => `/api/scan-runs/${runId}/reports/${format}${inline ? "?inline=true" : ""}`;
