// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const graphState = vi.hoisted(() => ({
  handlers: {} as Record<string, (event: { target: { id: string } }) => void>,
  data: undefined as { nodes: { id: string; data?: Record<string, unknown> }[]; edges: { id: string; source: string; target: string }[] } | undefined,
}));

vi.mock("@xyflow/react", async () => {
  const React = await import("react");
  return {
    Background: () => null, Controls: () => null, MiniMap: () => null,
    ReactFlowProvider: ({ children }: { children: React.ReactNode }) => React.createElement(React.Fragment, null, children),
    useReactFlow: () => ({ fitView: vi.fn() }),
    ReactFlow: (props: { nodes: NonNullable<typeof graphState.data>["nodes"]; edges: NonNullable<typeof graphState.data>["edges"]; onNodeClick: (event: React.MouseEvent, node: { id: string }) => void }) => {
      graphState.data = { nodes: props.nodes, edges: props.edges };
      graphState.handlers["node:click"] = (event) => {
        const node = props.nodes.find((candidate) => candidate.id === event.target.id);
        if (node) props.onNodeClick({} as React.MouseEvent, node);
      };
      if (props.edges.some((edge) => !props.nodes.some((node) => node.id === edge.source) || !props.nodes.some((node) => node.id === edge.target))) throw new Error("Flow edge endpoint is missing from current node set");
      return React.createElement("div", { "data-testid": "network-flow" }, props.nodes.map((node) => React.createElement("button", { key: node.id, onClick: () => props.onNodeClick({} as React.MouseEvent, node) }, String(node.data?.label || node.id))));
    },
  };
});

const calls: { path: string; params?: Record<string, string | boolean | undefined> }[] = [];
vi.mock("../auth/AuthContext", () => ({ useAuth: () => ({ atLeast: () => true }) }));
vi.mock("../api/client", async (original) => ({
  ...(await original<typeof import("../api/client")>()),
  api: vi.fn(async (path: string, options: { params?: Record<string, string | boolean | undefined> } = {}) => {
    calls.push({ path, params: options.params });
    if (path === "/map/summary") return { systems: [{ id: "si-1", name: "Production", description: "", children: [], exposure: { targets: 1, scanned_targets: 0, unscanned_targets: 1, severity: {} } }], totals: { systems: 1, targets: 1, scanned_targets: 0 } };
    if (path === "/map/zones") return [
      { id: "zone-1", name: "Public DMZ", description: "", zone_type: "dmz", parent_zone_id: null, cidr: "192.0.2.0/24", si_ids: ["si-1"], target_ids: ["host-1"], primary_target_ids: ["host-1"] },
      { id: "zone-child", name: "Application segment", description: "", zone_type: "vlan", parent_zone_id: "zone-1", cidr: "192.0.2.64/26", si_ids: ["si-1"], target_ids: [], primary_target_ids: [] },
    ];
    if (path === "/map/devices") return [];
    if (path === "/targets") return [{ id: "host-1", name: "web.example.test", value: "web.example.test", kind: "fqdn", ports: "443", description: "", owner_id: null, tags: [], si_ids: ["si-1"] }];
    if (path === "/information-systems") return [{ id: "si-1", name: "Production", description: "", parent_id: null }];
    if (path === "/map/graph") {
      if (options.params?.zone_id && options.params?.mode === "network") return {
        scope: { zone: { id: "zone-1", name: "Public DMZ" } }, mode: "network",
        nodes: [
          { id: "zone:zone-child", kind: "zone", name: "Application segment", zone_id: "zone-child", parent_zone_id: "zone-1", zone_type: "vlan" },
          { id: "device:child-device", kind: "device", name: "Application gateway", device_type: "gateway", zone_id: "zone-child" },
        ], links: [], truncated: false,
      };
      if (options.params?.zone_id) return { scope: { zone: { id: "zone-1", name: "Public DMZ" } }, mode: "si", nodes: [{ id: "target:host-1", kind: "host", name: "web.example.test", target_id: "host-1", value: "web.example.test", exposure: { run_id: "run-1", status: "completed", finished_at: "2026-01-01T12:00:00Z", endpoints: [{ endpoint_id: "endpoint-1", hostname: "web.example.test", ip_address: "192.0.2.20", port: 443, grade: "A", compliance_status: "compliant", highest_severity: null, tls_versions: ["TLS 1.3"], cipher_suites: [], certificate: null, errors: [], untested_checks: [], tls_checks: [] }], severity: { critical: 0, high: 0, medium: 0, low: 0 }, compliant: 1, non_compliant: 0, unevaluated: 0 } }], links: [], truncated: false };
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
  graphState.handlers = {};
  graphState.data = undefined;
  globalThis.ResizeObserver = class { observe() {} disconnect() {} unobserve() {} } as unknown as typeof ResizeObserver;
});

describe("Network Exposure Map", () => {
  it("progressively explores real SI, zone and host data without inventing scan results", async () => {
    render(<I18nProvider initial="en"><NetworkMap /></I18nProvider>);
    await screen.findByText("Network exposure map");
    await waitFor(() => expect(graphState.data?.nodes[0]?.id).toBe("si:si-1"));

    act(() => graphState.handlers["node:click"]?.({ target: { id: "si:si-1" } }));
    await waitFor(() => expect(calls.some((item) => item.path === "/map/graph" && item.params?.si_id === "si-1")).toBe(true));
    await waitFor(() => expect(graphState.data?.nodes[0]?.id).toBe("zone:zone-1"));

    act(() => graphState.handlers["node:click"]?.({ target: { id: "zone:zone-1" } }));
    await waitFor(() => expect(calls.some((item) => item.path === "/map/graph" && item.params?.zone_id === "zone-1")).toBe(true));
    await waitFor(() => expect(graphState.data?.nodes[0]?.id).toBe("target:host-1"));
    await waitFor(() => expect(graphState.data?.nodes.find((node) => node.id === "target:host-1")?.data?.endpoints).toEqual(expect.arrayContaining([expect.objectContaining({ hostname: "web.example.test", port: 443 })])));
    act(() => graphState.handlers["node:click"]?.({ target: { id: "target:host-1" } }));
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
    await waitFor(() => expect(graphState.data?.edges).toEqual([{ id: "link:link-1", source: "device:device-1", target: "device:device-2", type: "smoothstep", data: { provenance: "DECLARED" }, style: expect.any(Object) }]));
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
