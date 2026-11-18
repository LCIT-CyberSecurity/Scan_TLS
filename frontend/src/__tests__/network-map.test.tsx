// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";

const graphState = vi.hoisted(() => ({
  handlers: {} as Record<string, (event: { target: { id: string } }) => void>,
  data: undefined as { nodes: { id: string; data?: Record<string, unknown> }[]; edges: { source: string; target: string }[]; combos: unknown[] } | undefined,
  nodeType: undefined as unknown,
}));

vi.mock("@antv/g6", () => ({
  NodeEvent: { CLICK: "node:click" },
  ExtensionCategory: { NODE: "node" },
  register: vi.fn(),
  Circle: class {
    render() {}
    getSize(attributes: { size?: [number, number] }) { return attributes.size ?? [148, 148]; }
    upsert() {}
  },
  Rect: class {
    render() {}
    getSize(attributes: { size?: [number, number] }) { return attributes.size ?? [232, 116]; }
    upsert() {}
  },
  Graph: class {
    constructor(options: { node?: { type?: unknown } }) { graphState.nodeType = options.node?.type; }
    on(event: string, handler: (event: { target: { id: string } }) => void) { graphState.handlers[event] = handler; return this; }
    setData(data: typeof graphState.data) {
      if (data?.edges.some((edge) => !data.nodes.some((node) => node.id === edge.source) || !data.nodes.some((node) => node.id === edge.target))) {
        throw new Error("Graph edge endpoint is missing from current node set");
      }
      graphState.data = data;
    }
    render() { return Promise.resolve(); }
    fitView() { return Promise.resolve(); }
    resize() {}
    destroy() {}
    zoomBy() { return Promise.resolve(); }
    setElementState() {}
    getNodeData(id: string) { return graphState.data?.nodes.find((node) => node.id === id); }
  },
}));

const calls: { path: string; params?: Record<string, string | boolean | undefined>; body?: unknown }[] = [];
let showServiceObservations = false;
vi.mock("../auth/AuthContext", () => ({ useAuth: () => ({ atLeast: () => true }) }));
vi.mock("../api/client", async (original) => ({
  ...(await original<typeof import("../api/client")>()),
  api: vi.fn(async (path: string, options: { params?: Record<string, string | boolean | undefined>; body?: unknown } = {}) => {
    calls.push({ path, params: options.params, body: options.body });
    if (path === "/map/summary") return { systems: [{ id: "si-1", name: "Production", description: "", children: [], exposure: { targets: 1, scanned_targets: 0, unscanned_targets: 1, severity: {} } }], totals: { systems: 1, targets: 1, scanned_targets: 0 } };
    if (path === "/map/zones") return [
      { id: "zone-1", name: "Public DMZ", description: "", zone_type: "dmz", parent_zone_id: null, cidr: "192.0.2.0/24", si_ids: ["si-1"], target_ids: ["host-1"], primary_target_ids: ["host-1"] },
      { id: "zone-child", name: "Application segment", description: "", zone_type: "vlan", parent_zone_id: "zone-1", cidr: "192.0.2.64/26", si_ids: ["si-1"], target_ids: [], primary_target_ids: [] },
    ];
    if (path === "/map/devices") return [];
    if (path === "/targets") return [
      { id: "host-1", name: "web.example.test", value: "web.example.test", kind: "fqdn", ports: "443", description: "", owner_id: null, tags: [], si_ids: ["si-1"] },
      { id: "ip-1", name: "switch IP", value: "192.0.2.10", kind: "ip", ports: "", description: "", owner_id: null, tags: [], si_ids: ["si-1"] },
    ];
    if (path === "/information-systems") return [{ id: "si-1", name: "Production", description: "", parent_id: null }];
    if (path === "/map/graph") {
      if (options.params?.zone_id && options.params?.mode === "network") return {
        scope: { zone: { id: "zone-1", name: "Public DMZ" } }, mode: "network",
        nodes: [
          { id: "zone:zone-child", kind: "zone", name: "Application segment", zone_id: "zone-child", parent_zone_id: "zone-1", zone_type: "vlan" },
          { id: "device:child-device", kind: "device", name: "Application gateway", device_type: "gateway", zone_id: "zone-child" },
        ], links: [], truncated: false,
      };
      if (options.params?.zone_id) return { scope: { zone: { id: "zone-1", name: "Public DMZ" } }, mode: "si", nodes: [{ id: "target:host-1", kind: "host", name: "web.example.test", target_id: "host-1", value: "web.example.test", exposure: null }], links: [], truncated: false };
      if (options.params?.si_id && options.params?.mode === "network") return {
        scope: { si: { id: "si-1", name: "Production", description: "" } }, mode: "network",
        nodes: [
          { id: "zone:zone-1", kind: "zone", name: "Public DMZ", zone_id: "zone-1", zone_type: "dmz" },
          { id: "device:device-1", kind: "device", name: "Edge firewall", device_type: "firewall", zone_id: "zone-1" },
          { id: "device:device-2", kind: "device", name: "Core router", device_type: "router", zone_id: "zone-1" },
          { id: "device:child-device", kind: "device", name: "Application gateway", device_type: "gateway", zone_id: "zone-child" },
        ],
        links: [{ id: "link-1", source_device_id: "device-1", target_device_id: "device-2", provenance: "DECLARED" }], truncated: false,
      };
      if (options.params?.si_id) return { scope: { si: { id: "si-1", name: "Production", description: "" } }, mode: "si", nodes: [{ id: "zone:zone-1", kind: "zone", name: "Public DMZ", zone_id: "zone-1", zone_type: "dmz" }], links: [], truncated: false };
      return { scope: {}, mode: "si", nodes: [{ id: "si:si-1", kind: "si", name: "Production", si_id: "si-1", exposure: { targets: 1, scanned_targets: 0, unscanned_targets: 1, severity: {} } }], links: [], truncated: false };
    }
    if (path === "/map/hosts/host-1") return { target: { id: "host-1", name: "web.example.test", value: "web.example.test", kind: "fqdn", ports: "443", description: "", owner_id: null, tags: [], si_ids: ["si-1"], zones: [{ id: "zone-1", name: "Public DMZ" }] }, scan: showServiceObservations ? { run_id: "run-1", status: "completed", finished_at: "2026-01-01T12:00:00Z", endpoints: [], severity: {}, compliant: 0, non_compliant: 0, unevaluated: 0, services: [{ target: "web.example.test", address: "192.0.2.10", port: 8080, transport: "tcp", service: "http", product: "nginx", version: "1.25", confidence: 0.9, status: "observed", source: "Nmap -sV service probe" }], service_scan_finished_at: "2026-01-01T12:00:00Z" } : null, findings: [] };
    if (path === "/map/search") return [{ kind: "host", id: "host-1", name: "web.example.test", value: "web.example.test" }];
    return [];
  }),
}));

import NetworkMap from "../pages/NetworkMap";
import { I18nProvider } from "../i18n";

afterEach(cleanup);
beforeEach(() => {
  calls.length = 0;
  showServiceObservations = false;
  graphState.handlers = {};
  graphState.data = undefined;
  graphState.nodeType = undefined;
  globalThis.ResizeObserver = class { observe() {} disconnect() {} unobserve() {} } as unknown as typeof ResizeObserver;
});

describe("Network Exposure Map", () => {
  it("progressively explores real SI, zone and host data without inventing scan results", async () => {
    render(<MemoryRouter><I18nProvider initial="en"><NetworkMap /></I18nProvider></MemoryRouter>);
    await screen.findByText("Network exposure map");
    expect(typeof graphState.nodeType).toBe("function");
    expect((graphState.nodeType as (datum: { type?: string }) => string)({ type: "network-exposure-host-circle" })).toBe("network-exposure-host-circle");
    await waitFor(() => expect(graphState.data?.nodes[0]?.id).toBe("si:si-1"));

    act(() => graphState.handlers["node:click"]?.({ target: { id: "si:si-1" } }));
    await waitFor(() => expect(calls.some((item) => item.path === "/map/graph" && item.params?.si_id === "si-1")).toBe(true));
    await waitFor(() => expect(graphState.data?.nodes[0]?.id).toBe("zone:zone-1"));

    act(() => graphState.handlers["node:click"]?.({ target: { id: "zone:zone-1" } }));
    await waitFor(() => expect(calls.some((item) => item.path === "/map/graph" && item.params?.zone_id === "zone-1")).toBe(true));
    await waitFor(() => expect(graphState.data?.nodes[0]?.id).toBe("target:host-1"));
    act(() => graphState.handlers["node:click"]?.({ target: { id: "target:host-1" } }));
    expect(await screen.findByText("No TLS scan result is associated with this target.")).toBeInTheDocument();
  });

  it("returns from a LAN to its parent view with Escape or the visible close control", async () => {
    render(<MemoryRouter><I18nProvider initial="en"><NetworkMap /></I18nProvider></MemoryRouter>);
    await screen.findByText("Network exposure map");
    await waitFor(() => expect(graphState.data?.nodes[0]?.id).toBe("si:si-1"));

    act(() => graphState.handlers["node:click"]?.({ target: { id: "si:si-1" } }));
    await waitFor(() => expect(graphState.data?.nodes[0]?.id).toBe("zone:zone-1"));
    act(() => graphState.handlers["node:click"]?.({ target: { id: "zone:zone-1" } }));
    expect(await screen.findByRole("button", { name: "Back to parent view" })).toBeInTheDocument();
    fireEvent.keyDown(window, { key: "Escape" });
    await waitFor(() => expect(calls.some((item) => item.path === "/map/graph" && item.params?.si_id === "si-1" && !item.params?.zone_id)).toBe(true));

    act(() => graphState.handlers["node:click"]?.({ target: { id: "zone:zone-1" } }));
    fireEvent.click(await screen.findByRole("button", { name: "Back to parent view" }));
    await waitFor(() => expect(graphState.data?.nodes[0]?.id).toBe("zone:zone-1"));
    expect(calls.some((item) => item.path === "/map/graph" && item.params?.si_id === "si-1" && !item.params?.zone_id)).toBe(true);
  });

  it("supports a global search that opens the actual target detail", async () => {
    render(<I18nProvider initial="en"><NetworkMap /></I18nProvider>);
    const search = await screen.findByPlaceholderText("Search systems, zones, hosts or IPs");
    fireEvent.change(search, { target: { value: "web.example.test" } });
    fireEvent.keyDown(search, { key: "Enter" });
    fireEvent.click(await screen.findByRole("button", { name: /web.example.test/ }));
    expect(await screen.findByText("No TLS scan result is associated with this target.")).toBeInTheDocument();
    expect(calls.some((item) => item.path === "/map/hosts/host-1")).toBe(true);
  });

  it("shows service evidence and its observation time in the host panel", async () => {
    showServiceObservations = true;
    render(<MemoryRouter><I18nProvider initial="en"><NetworkMap /></I18nProvider></MemoryRouter>);
    const search = await screen.findByPlaceholderText("Search systems, zones, hosts or IPs");
    fireEvent.change(search, { target: { value: "web.example.test" } });
    fireEvent.keyDown(search, { key: "Enter" });
    fireEvent.click(await screen.findByRole("button", { name: /web.example.test/ }));
    expect(await screen.findByText("http")).toBeInTheDocument();
    expect(screen.getByText("nginx 1.25")).toBeInTheDocument();
    expect(screen.getByText(/Nmap -sV service probe/)).toBeInTheDocument();
    expect(screen.getByText(/Last service observation:/)).toBeInTheDocument();
  });

  it("does not load the full target inventory until an edit form is opened", async () => {
    render(<I18nProvider initial="en"><NetworkMap /></I18nProvider>);
    await screen.findByText("Network exposure map");
    await waitFor(() => expect(calls.some((item) => item.path === "/map/summary")).toBe(true));
    expect(calls.some((item) => item.path === "/targets")).toBe(false);
    fireEvent.change(screen.getByLabelText("Information systems"), { target: { value: "si-1" } });
    fireEvent.click((await screen.findAllByRole("button", { name: "New zone" }))[0]);
    await waitFor(() => expect(calls.some((item) => item.path === "/targets")).toBe(true));
  });

  it("never submits stale network links without their matching device nodes", async () => {
    render(<I18nProvider initial="en"><NetworkMap /></I18nProvider>);
    await screen.findByText("Network exposure map");
    await screen.findByRole("option", { name: "Production" });
    fireEvent.change(screen.getByLabelText("Information systems"), { target: { value: "si-1" } });
    await waitFor(() => expect(graphState.data?.nodes[0]?.id).toBe("zone:zone-1"));
    fireEvent.click(screen.getByRole("button", { name: "Network architecture" }));
    await waitFor(() => expect(graphState.data?.edges).toEqual([{ id: "link:link-1", source: "device:device-1", target: "device:device-2", type: "line", data: { provenance: "DECLARED" }, style: expect.any(Object) }]));
  });

  it("reveals nested-zone equipment only after entering its parent zone", async () => {
    render(<I18nProvider initial="en"><NetworkMap /></I18nProvider>);
    await screen.findByText("Network exposure map");
    await screen.findByRole("option", { name: "Production" });
    fireEvent.change(screen.getByLabelText("Information systems"), { target: { value: "si-1" } });
    await waitFor(() => expect(graphState.data?.nodes.some((node) => node.id === "zone:zone-1")).toBe(true));

    const networkRequest = waitFor(() => expect(calls.some((item) => item.path === "/map/graph" && item.params?.si_id === "si-1" && item.params?.mode === "network")).toBe(true));
    fireEvent.click(screen.getByRole("button", { name: "Network architecture" }));
    await networkRequest;
    await waitFor(() => expect(graphState.data?.nodes.some((node) => node.id === "device:child-device")).toBe(false));

    act(() => graphState.handlers["node:click"]?.({ target: { id: "zone:zone-1" } }));
    await waitFor(() => expect(graphState.data?.nodes.some((node) => node.id === "device:child-device")).toBe(true));
  });

});
