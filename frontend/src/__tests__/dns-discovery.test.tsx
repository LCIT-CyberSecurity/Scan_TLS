// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DnsDiscoveryDialog } from "../components/DnsDiscovery";
import { I18nProvider } from "../i18n";

const calls: { path: string; method: string; body?: any; params?: any }[] = []; // eslint-disable-line @typescript-eslint/no-explicit-any
let handlers: Record<string, (body?: any, params?: any) => unknown> = {}; // eslint-disable-line @typescript-eslint/no-explicit-any
vi.mock("../api/client", async (original) => ({
  ...(await original<typeof import("../api/client")>()),
  api: vi.fn(async (path: string, options: { method?: string; body?: unknown; params?: Record<string, string> } = {}) => {
    calls.push({ path, method: options.method ?? "GET", body: options.body, params: options.params });
    const handler = handlers[`${options.method ?? "GET"} ${path}`];
    if (!handler) throw new Error(`unexpected call ${options.method ?? "GET"} ${path}`);
    return handler(options.body, options.params);
  }),
}));

afterEach(cleanup);
beforeEach(() => {
  calls.length = 0;
  handlers = {
    "GET /targets/discover-config": () => ({ allowed_servers: ["10.10.0.10:53"], ct_enabled: true, limits: { max_apply_items: 500 } }),
    "GET /information-systems": () => [], "GET /target-groups": () => [{ id: "g1", name: "Existing group", target_ids: [], tags: [], si_ids: [], description: "", owner_id: null }],
  };
});
const wrap = () => render(<I18nProvider><DnsDiscoveryDialog onClose={() => undefined} onDone={() => undefined} /></I18nProvider>);

const item = (fqdn: string, extra: Record<string, unknown> = {}) => ({ fqdn, in_scope: true, types: ["A"], ips: ["10.0.0.1"], cnames: [], sources: ["axfr"], roles: [], resolved: true, wildcard: false, notes: [], inventory: "NEW", matches: [], ambiguous: false, diff: null, ...extra });
const results = (items: unknown[]) => ({ total: items.length, counts: { NEW: 2, ENRICHABLE: 1, OUT_OF_SCOPE: 1 }, sources: { axfr: 4, dictionary: 1 }, items, offset: 0, limit: 100,
  methods: { dns: { status: "done", detail: "", found: 2 }, axfr: { status: "done", detail: "1/1 transferred", found: 3 } },
  nameservers: [{ name: "ns1.client.test", address: "10.10.0.10", status: "transferred", records: 3, source: "ns" }],
  security: [], transfer_possible: true, truncated: false, partial: false, resolver: "10.10.0.10:53" });
const ROWS = [item("srv01.client.test"), item("gitlab.client.test"), item("vpn.client.test", { inventory: "ENRICHABLE", matches: [{ id: "t1", ports: "8443", name: "", status: "ENRICHABLE" }], diff: { new_ips: ["10.0.0.9"], missing_ips: [], new_cnames: [], new_sources: [], cname_changed: false } }),
  item("mx.partner.example", { in_scope: false, inventory: "OUT_OF_SCOPE" })];

describe("DNS discovery wizard", () => {
  it("fast mode: no server, dictionary or reverse option; the start button needs the authorisation", async () => {
    wrap();
    await screen.findByLabelText("Domain");
    expect(screen.queryByText("Advanced options")).toBeNull();
    expect(screen.queryByLabelText(/Reverse DNS/)).toBeNull();
    const start = screen.getByRole("button", { name: /Start discovery/ });
    fireEvent.change(screen.getByLabelText("Domain"), { target: { value: "client.test" } });
    expect(start).toBeDisabled();
    fireEvent.click(screen.getByLabelText(/I confirm that I am authorised/));
    expect(start).toBeEnabled();
  });

  it("advanced mode offers only the administrator-declared servers and sends them", async () => {
    handlers["POST /targets/discover"] = (body) => ({ id: "d1", domain: body.domain, status: "queued", error: "", cancel_requested: false, options: body, progress: null });
    wrap();
    fireEvent.change(await screen.findByLabelText("Mode"), { target: { value: "advanced" } });
    const server = await screen.findByLabelText("DNS server to query");
    expect(within(server as HTMLElement).getAllByRole("option").map((o) => o.textContent)).toEqual(["Resolver configured on the worker", "10.10.0.10:53"]);
    fireEvent.change(server, { target: { value: "10.10.0.10:53" } });
    fireEvent.click(screen.getByLabelText(/Reverse DNS/));
    fireEvent.change(screen.getByLabelText(/IP addresses or networks/), { target: { value: "192.0.2.0/28" } });
    fireEvent.change(screen.getByLabelText("Domain"), { target: { value: "client.test" } });
    fireEvent.click(screen.getByLabelText(/I confirm that I am authorised/));
    fireEvent.click(screen.getByRole("button", { name: /Start discovery/ }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/targets/discover")).toBe(true));
    const body = calls.find((c) => c.method === "POST")!.body;
    expect(body).toMatchObject({ domain: "client.test", mode: "advanced", dns_server: "10.10.0.10:53", reverse: ["192.0.2.0/28"], dictionary: "small" });
    expect(body.methods).toEqual(["dns", "axfr", "dictionary", "ct", "reverse"]);
    expect(await screen.findByText(/Waiting for the worker/)).toBeInTheDocument();
    expect(screen.queryByRole("progressbar")).toBeNull();  // no percentage when the total is unknown
  });

  it("results -> selection -> exact plan -> grouped apply, with confirmation for business changes", async () => {
    handlers["POST /targets/discover"] = () => ({ id: "d1", domain: "client.test", status: "done", error: "", cancel_requested: false, options: {}, progress: null });
    handlers["GET /targets/discover/d1"] = () => ({ id: "d1", domain: "client.test", status: "done", error: "", cancel_requested: false, options: {}, progress: null });
    handlers["GET /targets/discover/d1/results"] = (_b, params) => results(params?.inventory === "NEW" ? ROWS.filter((r) => r.inventory === "NEW") : params?.inventory === "ENRICHABLE" ? ROWS.filter((r) => r.inventory === "ENRICHABLE") : ROWS);
    const plan = (body: any) => ({ dry_run: body.dry_run, applied: !body.dry_run, group: null, // eslint-disable-line @typescript-eslint/no-explicit-any
      summary: { create: body.items.filter((i: any) => i.action === "add").length, reuse: 0, enrich: body.items.filter((i: any) => i.action === "enrich").length, skipped: 0, business_changes_pending_confirmation: body.confirm_business_changes ? 0 : 1 }, // eslint-disable-line @typescript-eslint/no-explicit-any
      items: body.items.map((i: any) => ({ fqdn: i.fqdn, outcome: i.action === "add" ? "create" : "enrich", reason: "", target_id: i.target_id ?? null, dns: { new_ips: ["10.0.0.9"], missing_ips: [] }, // eslint-disable-line @typescript-eslint/no-explicit-any
        business_changes: i.action === "enrich" ? { tags_added: ["x"], si_added: [], group_added: false } : undefined })) });
    handlers["POST /targets/discover/d1/apply"] = plan;
    wrap();
    fireEvent.change(await screen.findByLabelText("Domain"), { target: { value: "client.test" } });
    fireEvent.click(screen.getByLabelText(/I confirm that I am authorised/));
    fireEvent.click(screen.getByRole("button", { name: /Start discovery/ }));
    expect(await screen.findByText("srv01.client.test")).toBeInTheDocument();
    // an out-of-perimeter name cannot be selected
    expect(screen.getByLabelText("mx.partner.example")).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Select the new ones" }));
    await waitFor(() => expect(screen.getByText("2 selected")).toBeInTheDocument());
    fireEvent.click(screen.getByLabelText("vpn.client.test"));
    expect(screen.getByText("3 selected")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Review the selection/ }));
    expect(await screen.findByText("2 new target(s) will be created")).toBeInTheDocument();
    expect(screen.getByText("1 target(s) enriched with DNS observations")).toBeInTheDocument();
    expect(screen.getByText("No scan is started and no scan definition is modified.")).toBeInTheDocument();
    const dry = calls.filter((c) => c.path.endsWith("/apply")).at(-1)!.body;
    expect(dry).toMatchObject({ dry_run: true, confirm_business_changes: false });
    expect(dry.items).toEqual(expect.arrayContaining([{ fqdn: "vpn.client.test", action: "enrich", target_id: "t1" }, { fqdn: "srv01.client.test", action: "add" }]));
    // tags on existing targets are only applied once confirmed
    fireEvent.click(await screen.findByLabelText(/Also apply the tags, SI and group/));
    await waitFor(() => expect(calls.filter((c) => c.path.endsWith("/apply")).at(-1)!.body.confirm_business_changes).toBe(true));
    fireEvent.click(screen.getByRole("button", { name: "Add / Enrich the targets" }));
    await screen.findByText(/Done: 2 created, 0 kept, 1 enriched, 0 not processed\./);
    const applied = calls.filter((c) => c.path.endsWith("/apply") && c.body.dry_run === false);
    expect(applied).toHaveLength(1);                                  // one grouped request for the whole selection
  });

  it("explains a failed discovery and keeps the partial banner", async () => {
    handlers["POST /targets/discover"] = () => ({ id: "d2", domain: "client.test", status: "failed", error: "No DNS method succeeded (dns: timeout)", cancel_requested: false, options: {}, progress: null });
    handlers["GET /targets/discover/d2"] = () => ({ id: "d2", domain: "client.test", status: "failed", error: "No DNS method succeeded (dns: timeout)", cancel_requested: false, options: {}, progress: null });
    handlers["GET /targets/discover/d2/results"] = () => ({ ...results([]), partial: true, counts: {}, sources: {} });
    wrap();
    fireEvent.change(await screen.findByLabelText("Domain"), { target: { value: "client.test" } });
    fireEvent.click(screen.getByLabelText(/I confirm that I am authorised/));
    fireEvent.click(screen.getByRole("button", { name: /Start discovery/ }));
    expect(await screen.findByText(/No DNS method succeeded/)).toBeInTheDocument();
    expect(screen.getByText(/results below are partial/)).toBeInTheDocument();
  });
});
