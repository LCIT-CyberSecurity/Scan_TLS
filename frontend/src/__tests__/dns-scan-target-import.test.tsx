// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "../test-utils";
import { MemoryRouter } from "react-router-dom";
import Scans from "../pages/Scans";
import { I18nProvider } from "../i18n";

const calls: { path: string; method: string; body?: any; params?: Record<string, string> }[] = []; // eslint-disable-line @typescript-eslint/no-explicit-any
let targets: any[] = []; // eslint-disable-line @typescript-eslint/no-explicit-any
vi.mock("../auth/AuthContext", () => ({ useAuth: () => ({ user: { id: "u1" }, atLeast: () => true }) }));
vi.mock("../api/client", async (original) => ({
  ...(await original<typeof import("../api/client")>()),
  api: vi.fn(async (path: string, options: { method?: string; body?: any; params?: Record<string, string> } = {}) => { // eslint-disable-line @typescript-eslint/no-explicit-any
    calls.push({ path, method: options.method ?? "GET", body: options.body, params: options.params });
    if (["/scan-runs", "/scan-definitions", "/target-groups", "/report-templates", "/information-systems"].includes(path) || path.startsWith("/policies") || path.startsWith("/profiles")) return [];
    if (path === "/targets") return targets;
    if (path === "/targets/discover") return [{ id: "disc-1", domain: "example.test", status: "done", created_at: "2026-11-17T10:00:00Z" }];
    if (path === "/targets/discover/disc-1/results") {
      const base = { in_scope: true, types: ["A"], ips: ["192.0.2.10"], cnames: [], sources: ["dns"], roles: [], resolved: true, wildcard: false, notes: [], coverage: { covered: false, definitions: [], definitions_total: 0, shared_address: [], recently_scanned: false, last_scan: null }, ambiguous: false, diff: null };
      const fresh = { ...base, fqdn: "api.example.test", inventory: "NEW", matches: [] };
      const existing = { ...base, fqdn: "known.example.test", inventory: "EXISTING", matches: [{ id: "target-known", ports: "443", name: "", status: "EXISTING" }] };
      const filtered = options.params?.inventory === "NEW";
      return { total: filtered ? 1 : 2, counts: { NEW: 1, EXISTING: 1 }, sources: { dns: 2 }, offset: Number(options.params?.offset ?? 0), limit: Number(options.params?.limit ?? 100), items: filtered ? [fresh] : [fresh, existing], methods: {}, nameservers: [], security: [], transfer_possible: false, truncated: false, partial: false, resolver: "system", recent_scan_days: 7, covered: 0, recently_scanned: 0, discovery_tag: "DNS", default_group: { name: "DNS — example.test", id: null, exists: false } };
    }
    if (path === "/targets/discover/disc-1/apply") {
      const body = options.body!;
      const report = { dry_run: body.dry_run, applied: !body.dry_run, discovery_id: "disc-1", tag: null, summary: { create: 1, reuse: 0, enrich: 0, skipped: 0, business_changes_pending_confirmation: 0 }, group: null, items: [{ fqdn: "api.example.test", outcome: "create", reason: "", target_id: body.dry_run ? null : "target-1" }] };
      if (!body.dry_run) targets = [{ id: "target-1", name: "", value: "api.example.test", kind: "fqdn", ports: "443", description: "DNS discovery", owner_id: "u1", tags: [], si_ids: [] }];
      return report;
    }
    throw new Error(`unexpected request: ${options.method ?? "GET"} ${path}`);
  }),
}));

afterEach(cleanup);
beforeEach(() => { calls.length = 0; targets = []; });

describe("DNS endpoint import in scan definition", () => {
  it("previews missing endpoints, requires confirmation, and selects the imported target", async () => {
    render(<MemoryRouter><I18nProvider initial="en"><Scans /></I18nProvider></MemoryRouter>);
    fireEvent.click(await screen.findByRole("button", { name: "New scan" }));
    fireEvent.change(await screen.findByLabelText("DNS discovery"), { target: { value: "disc-1" } });
    expect(await screen.findByText("known.example.test")).toBeInTheDocument();
    expect(screen.getByRole("checkbox", { name: /known.example.test/ })).toBeDisabled();
    fireEvent.click(await screen.findByRole("button", { name: "Select all missing endpoints" }));
    await waitFor(() => expect(screen.getByText(/2 discovered endpoints · 1 selected/)).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: /Preview import/ }));
    expect(await screen.findByText("1 new target(s), 0 existing target(s), 0 conflict(s)")).toBeInTheDocument();
    expect(calls.find((call) => call.path.endsWith("/apply"))?.body).toMatchObject({ dry_run: true, discovery_tag: false, items: [{ fqdn: "api.example.test", action: "add" }] });
    fireEvent.click(screen.getByRole("button", { name: "Confirm and add to Targets" }));
    expect(await screen.findByText(/1 target\(s\) added or matched/)).toBeInTheDocument();
    await waitFor(() => expect(screen.getAllByLabelText(/api.example.test/).some((input) => (input as HTMLInputElement).checked)).toBe(true));
    expect(calls.filter((call) => call.path.endsWith("/apply")).map((call) => call.body.dry_run)).toEqual([true, false]);
  });
});
