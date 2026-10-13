// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DiscoveriesTab, DnsDiscoveryDialog } from "../components/DnsDiscovery";
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
    "GET /information-systems": () => [], "GET /scan-definitions": () => [{ id: "def1", name: "Weekly external" }], "GET /profiles": () => [{ id: "pr1", name: "Standard", archived: false, versions: [{ status: "published" }] }],
    "GET /policies": () => [{ id: "po1", name: "ANSSI", archived: false, versions: [{ status: "published" }] }], "GET /target-groups": () => [{ id: "g1", name: "Existing group", target_ids: [], tags: [], si_ids: [], description: "", owner_id: null }],
  };
});
const wrap = () => render(<I18nProvider><DnsDiscoveryDialog onClose={() => undefined} onDone={() => undefined} /></I18nProvider>);

const NOT_COVERED = { covered: false, definitions: [], definitions_total: 0, shared_address: [], recently_scanned: false, last_scan: null };
const item = (fqdn: string, extra: Record<string, unknown> = {}) => ({ fqdn, in_scope: true, types: ["A"], ips: ["10.0.0.1"], cnames: [], sources: ["axfr"], roles: [], resolved: true, wildcard: false, notes: [], inventory: "NEW", matches: [], ambiguous: false, diff: null, coverage: NOT_COVERED, ...extra });
const results = (items: unknown[]) => ({ total: items.length, counts: { NEW: 2, ENRICHABLE: 1, OUT_OF_SCOPE: 1 }, sources: { axfr: 4, dictionary: 1 }, items, offset: 0, limit: 100,
  methods: { dns: { status: "done", detail: "", found: 2 }, axfr: { status: "done", detail: "1/1 transferred", found: 3 } },
  nameservers: [{ name: "ns1.client.test", address: "10.10.0.10", status: "transferred", records: 3, source: "ns" }],
  security: [], transfer_possible: true, truncated: false, partial: false, resolver: "10.10.0.10:53",
  recent_scan_days: 7, covered: (items as any[]).filter((i) => i.coverage.covered).length, recently_scanned: (items as any[]).filter((i) => i.coverage.recently_scanned).length }); // eslint-disable-line @typescript-eslint/no-explicit-any
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

  it("names already in a scan are shown as covered and left unchecked by the bulk selections", async () => {
    const covered = item("gitlab.client.test", { coverage: { ...NOT_COVERED, covered: true, definitions: [{ id: "def1", name: "Weekly external", via: "group", group: "Perimeter", scheduled: true }], definitions_total: 1 } });
    const recent = item("vpn.client.test", { coverage: { ...NOT_COVERED, recently_scanned: true, last_scan: { run_id: "r1", name: "x", finished_at: "2026-10-10T10:00:00Z" } } });
    const rows = [item("srv01.client.test"), covered, recent];
    handlers["POST /targets/discover"] = () => ({ id: "d1", domain: "client.test", status: "done", error: "", cancel_requested: false, options: {}, progress: null });
    handlers["GET /targets/discover/d1"] = () => ({ id: "d1", domain: "client.test", status: "done", error: "", cancel_requested: false, options: {}, progress: null });
    handlers["GET /targets/discover/d1/results"] = () => results(rows);
    handlers["POST /targets/discover/d1/apply"] = (body: any) => ({ dry_run: body.dry_run, applied: !body.dry_run, group: { id: null, name: body.group_name, will_create: true }, // eslint-disable-line @typescript-eslint/no-explicit-any
      summary: { create: body.items.length, reuse: 0, enrich: 0, skipped: 0, business_changes_pending_confirmation: 0 },
      definitions: body.new_definition ? [{ id: null, name: body.new_definition.name, action: "create", scheduled: false }] : [],
      items: body.items.map((i: any) => ({ fqdn: i.fqdn, outcome: "create", reason: "", target_id: null })) }); // eslint-disable-line @typescript-eslint/no-explicit-any
    wrap();
    fireEvent.change(await screen.findByLabelText("Domain"), { target: { value: "client.test" } });
    fireEvent.click(screen.getByLabelText(/I confirm that I am authorised/));
    fireEvent.click(screen.getByRole("button", { name: /Start discovery/ }));
    await screen.findByText("srv01.client.test");
    expect(screen.getByText(/1 name\(s\) already covered by a scan, 1 scanned within the last 7 days/)).toBeInTheDocument();
    expect(screen.getByText("Weekly external")).toBeInTheDocument();
    expect(screen.getByText(/via group Perimeter/)).toBeInTheDocument();
    expect(screen.getByText("Recently scanned")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Select all (current filter)" }));
    await waitFor(() => expect(screen.getByText("1 selected")).toBeInTheDocument());          // only the name no scan knows about
    fireEvent.click(screen.getByLabelText(/Also include the names already covered/));
    fireEvent.click(screen.getByRole("button", { name: "Select all (current filter)" }));
    await waitFor(() => expect(screen.getByText("3 selected")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Clear the selection" }));
    fireEvent.click(screen.getByLabelText("gitlab.client.test"));                                 // a covered name can still be ticked by hand
    expect(screen.getByText("1 selected")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Review the selection/ }));
    // choosing a scan creates the group it needs, and the new scan is described in the plan
    fireEvent.change(await screen.findByLabelText("Scan"), { target: { value: "new" } });
    expect((screen.getByLabelText("New group name") as HTMLInputElement).value).toContain("Discovery client.test");
    const apply = screen.getByRole("button", { name: "Add / Enrich the targets" });
    await waitFor(() => expect(apply).toBeDisabled());                                           // the new scan still lacks a profile and a policy
    fireEvent.change(screen.getByLabelText("Profile"), { target: { value: "pr1" } });
    fireEvent.click(await screen.findByLabelText("ANSSI"));
    await waitFor(() => expect(apply).toBeEnabled());
    const body = calls.filter((c) => c.path.endsWith("/apply")).at(-1)!.body;
    await waitFor(() => expect(calls.filter((c) => c.path.endsWith("/apply")).at(-1)!.body.new_definition).toEqual({ name: "Scan client.test", profile_id: "pr1", policy_ids: ["po1"] }));
    expect(body.group_name).toContain("Discovery client.test");
    expect(await screen.findByText(/The scan “Scan client.test” will be created \(not launched\)/)).toBeInTheDocument();
    expect(screen.getByText("No scan is started: you launch it yourself from Scans.")).toBeInTheDocument();
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


describe("DNS discoveries tab (history)", () => {
  beforeEach(() => { vi.spyOn(window, "confirm").mockReturnValue(true); });
  const row = (extra = {}) => ({ id: "d1", domain: "client.test", status: "done", error: "", created_at: "2026-10-13T08:00:00Z", finished_at: "2026-10-13T08:00:09Z", mode: "advanced", resolver: "10.10.0.10:53",
    methods: { dns: "done", axfr: "done", dictionary: "failed" }, names: 12, in_scope: 10, transfer_possible: true, partial: false, requested_by: "operator@example.com", ...extra });
  const mount = (onOpen = vi.fn(), onNew = vi.fn()) => { render(<I18nProvider><DiscoveriesTab onOpen={onOpen} onNew={onNew} reloadKey={0} /></I18nProvider>); return { onOpen, onNew }; };

  it("lists the discoveries with their state, counts and methods, and reopens one", async () => {
    handlers["GET /targets/discover"] = () => [row(), row({ id: "d2", domain: "other.test", status: "failed", error: "No DNS method succeeded (dns: timeout)", names: 0, in_scope: 0, methods: { dns: "failed" }, transfer_possible: false })];
    const { onOpen } = mount();
    const first = (await screen.findByText("client.test")).closest("tr")!;
    expect(within(first).getByText("Done")).toBeInTheDocument();
    expect(within(first).getByText("12")).toBeInTheDocument();
    expect(within(first).getByText(/10 in the domain · zone transfer accepted/)).toBeInTheDocument();
    expect(within(first).getByText("axfr")).toBeInTheDocument();
    expect(within(first).getByText("operator@example.com")).toBeInTheDocument();
    const failed = screen.getByText("other.test").closest("tr")!;
    expect(within(failed).getByText("Failed")).toBeInTheDocument();
    expect(within(failed).getByText(/No DNS method succeeded/)).toBeInTheDocument();
    fireEvent.click(within(first).getByRole("button", { name: "Open" }));
    expect(onOpen).toHaveBeenCalledWith("d1");
  });

  it("a running discovery can be opened but not deleted; a finished one is deleted after confirmation", async () => {
    handlers["GET /targets/discover"] = () => [row({ id: "r1", domain: "running.test", status: "running", methods: { dns: "running" } }), row()];
    handlers["DELETE /targets/discover/d1"] = () => undefined;
    mount();
    const running = (await screen.findByText("running.test")).closest("tr")!;
    expect(within(running).queryByRole("button", { name: "Delete" })).toBeNull();
    fireEvent.click(within(screen.getByText("client.test").closest("tr")!).getByRole("button", { name: "Delete" }));
    expect(window.confirm).toHaveBeenCalledWith(expect.stringMatching(/targets already imported are not affected/));
    await waitFor(() => expect(calls.some((c) => c.method === "DELETE" && c.path === "/targets/discover/d1")).toBe(true));
  });

  it("explains the empty state and offers a new discovery", async () => {
    handlers["GET /targets/discover"] = () => [];
    const { onNew } = mount();
    expect(await screen.findByText(/No DNS discovery yet/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "New discovery" }));
    expect(onNew).toHaveBeenCalled();
  });

  it("reopening a finished discovery goes straight to its results", async () => {
    handlers["GET /targets/discover/d1"] = () => ({ id: "d1", domain: "client.test", status: "done", error: "", cancel_requested: false, options: {}, progress: null });
    handlers["GET /targets/discover/d1/results"] = () => results(ROWS);
    render(<I18nProvider><DnsDiscoveryDialog resumeId="d1" onClose={() => undefined} onDone={() => undefined} /></I18nProvider>);
    expect(await screen.findByText("srv01.client.test")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Select all (current filter)" })).toBeInTheDocument();
    expect(calls.some((c) => c.method === "POST" && c.path === "/targets/discover")).toBe(false);   // nothing is relaunched
  });
});
