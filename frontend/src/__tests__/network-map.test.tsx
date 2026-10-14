// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const graphState = vi.hoisted(() => ({
  click: undefined as ((event: { target: { id: string } }) => void) | undefined,
  data: undefined as { nodes: { id: string; data?: Record<string, unknown> }[]; edges: unknown[]; combos: unknown[] } | undefined,
}));

vi.mock("@antv/g6", () => ({
  NodeEvent: { CLICK: "node:click" },
  ExtensionCategory: { NODE: "node" },
  register: vi.fn(),
  Rect: class {
    render() {}
    getSize(attributes: { size?: [number, number] }) { return attributes.size ?? [232, 116]; }
    upsert() {}
  },
  Graph: class {
    on(_event: string, handler: (event: { target: { id: string } }) => void) { graphState.click = handler; return this; }
    setData(data: typeof graphState.data) { graphState.data = data; }
    render() { return Promise.resolve(); }
    fitView() { return Promise.resolve(); }
    resize() {}
    destroy() {}
    zoomBy() { return Promise.resolve(); }
    setElementState() {}
    getNodeData(id: string) { return graphState.data?.nodes.find((node) => node.id === id); }
  },
}));

const calls: { path: string; params?: Record<string, string | boolean | undefined> }[] = [];
vi.mock("../auth/AuthContext", () => ({ useAuth: () => ({ atLeast: () => true }) }));
vi.mock("../api/client", async (original) => ({
  ...(await original<typeof import("../api/client")>()),
  api: vi.fn(async (path: string, options: { params?: Record<string, string | boolean | undefined> } = {}) => {
    calls.push({ path, params: options.params });
    if (path === "/map/summary") return { systems: [{ id: "si-1", name: "Production", description: "", children: [], exposure: { targets: 1, scanned_targets: 0, unscanned_targets: 1, severity: {} } }], totals: { systems: 1, targets: 1, scanned_targets: 0 } };
    if (path === "/map/zones") return [{ id: "zone-1", name: "Public DMZ", description: "", zone_type: "dmz", parent_zone_id: null, cidr: "192.0.2.0/24", si_ids: ["si-1"], target_ids: ["host-1"], primary_target_ids: ["host-1"] }];
    if (path === "/map/devices") return [];
    if (path === "/targets") return [{ id: "host-1", name: "web.example.test", value: "web.example.test", kind: "fqdn", ports: "443", description: "", owner_id: null, tags: [], si_ids: ["si-1"] }];
    if (path === "/information-systems") return [{ id: "si-1", name: "Production", description: "", parent_id: null }];
    if (path === "/map/graph") {
      if (options.params?.zone_id) return { scope: { zone: { id: "zone-1", name: "Public DMZ" } }, mode: "si", nodes: [{ id: "target:host-1", kind: "host", name: "web.example.test", target_id: "host-1", value: "web.example.test", exposure: null }], links: [], truncated: false };
      if (options.params?.si_id) return { scope: { si: { id: "si-1", name: "Production", description: "" } }, mode: "si", nodes: [{ id: "zone:zone-1", kind: "zone", name: "Public DMZ", zone_id: "zone-1", zone_type: "dmz" }], links: [], truncated: false };
      return { scope: {}, mode: "si", nodes: [{ id: "si:si-1", kind: "si", name: "Production", si_id: "si-1", exposure: { targets: 1, scanned_targets: 0, unscanned_targets: 1, severity: {} } }], links: [], truncated: false };
    }
    if (path === "/map/hosts/host-1") return { target: { id: "host-1", name: "web.example.test", value: "web.example.test", kind: "fqdn", ports: "443", description: "", owner_id: null, tags: [], si_ids: ["si-1"], zones: [{ id: "zone-1", name: "Public DMZ" }] }, scan: null, findings: [] };
    if (path === "/map/search") return [{ kind: "host", id: "host-1", name: "web.example.test", value: "web.example.test" }];
    return [];
  }),
}));

import NetworkMap from "../pages/NetworkMap";
import { I18nProvider } from "../i18n";

afterEach(cleanup);
beforeEach(() => {
  calls.length = 0;
  graphState.click = undefined;
  graphState.data = undefined;
  globalThis.ResizeObserver = class { observe() {} disconnect() {} unobserve() {} } as unknown as typeof ResizeObserver;
});

describe("Network Exposure Map", () => {
  it("progressively explores real SI, zone and host data without inventing scan results", async () => {
    render(<I18nProvider initial="en"><NetworkMap /></I18nProvider>);
    await screen.findByText("Network exposure map");
    await waitFor(() => expect(graphState.data?.nodes[0]?.id).toBe("si:si-1"));

    act(() => graphState.click?.({ target: { id: "si:si-1" } }));
    await waitFor(() => expect(calls.some((item) => item.path === "/map/graph" && item.params?.si_id === "si-1")).toBe(true));
    await waitFor(() => expect(graphState.data?.nodes[0]?.id).toBe("zone:zone-1"));

    act(() => graphState.click?.({ target: { id: "zone:zone-1" } }));
    await waitFor(() => expect(calls.some((item) => item.path === "/map/graph" && item.params?.zone_id === "zone-1")).toBe(true));
    await waitFor(() => expect(graphState.data?.nodes[0]?.id).toBe("target:host-1"));
    act(() => graphState.click?.({ target: { id: "target:host-1" } }));
    expect(await screen.findByText("No TLS scan result is associated with this target.")).toBeInTheDocument();
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

  it("does not load the full target inventory until an edit form is opened", async () => {
    render(<I18nProvider initial="en"><NetworkMap /></I18nProvider>);
    await screen.findByText("Network exposure map");
    await waitFor(() => expect(calls.some((item) => item.path === "/map/summary")).toBe(true));
    expect(calls.some((item) => item.path === "/targets")).toBe(false);
    fireEvent.change(screen.getByLabelText("Information systems"), { target: { value: "si-1" } });
    fireEvent.click(await screen.findByRole("button", { name: "New zone" }));
    await waitFor(() => expect(calls.some((item) => item.path === "/targets")).toBe(true));
  });
});
