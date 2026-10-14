import { describe, expect, it, vi } from "vitest";
import type { MapGraph, MapNode } from "../api/types";
import { mapCardAttributes, positionMapNodes } from "../lib/networkMapGraph";

vi.mock("@antv/g6", () => ({
  ExtensionCategory: { NODE: "node" },
  register: vi.fn(),
  Rect: class {
    render() {}
    getSize(attributes: { size?: [number, number] }) { return attributes.size ?? [232, 116]; }
    upsert() {}
  },
}));

const translate = (key: string) => key;

function siGraph(mode: MapGraph["mode"] = "si"): MapGraph {
  return { mode, scope: { si: { id: "si-1", name: "Production", description: "", parent_id: null } }, nodes: [], links: [], truncated: false };
}

describe("network map graph presentation", () => {
  it("uses deterministic, separated lanes for the progressive SI view", () => {
    const nodes: MapNode[] = [
      { id: "zone:z1", kind: "zone", zone_id: "z1", name: "DMZ" },
      { id: "system:s1", kind: "si", si_id: "s1", name: "Applications" },
      { id: "group:g1", kind: "group", group_id: "g1", name: "Public services" },
    ];
    const first = positionMapNodes(nodes, siGraph(), 1280);
    const second = positionMapNodes(nodes, siGraph(), 1280);
    expect(first).toEqual(second);
    expect(new Set(first.map(({ id }) => id)).size).toBe(nodes.length);
    expect(first.find(({ id }) => id === "system:s1")?.y).toBeLessThan(first.find(({ id }) => id === "zone:z1")?.y ?? 0);
    expect(first.find(({ id }) => id === "zone:z1")?.y).toBeLessThan(first.find(({ id }) => id === "group:g1")?.y ?? 0);
  });

  it("groups zone devices only by their explicit zone association", () => {
    const graph = siGraph("network");
    const nodes: MapNode[] = [
      { id: "zone:z1", kind: "zone", zone_id: "z1", name: "DMZ" },
      { id: "device:d1", kind: "device", zone_id: "z1", name: "Edge firewall", device_type: "firewall" },
      { id: "device:d2", kind: "device", zone_id: "z1", name: "Core router", device_type: "router" },
    ];
    const positions = positionMapNodes(nodes, graph, 1440);
    const groupIds = new Set(positions.map(({ combo }) => combo));
    expect(groupIds).toEqual(new Set(["zone-group:z1"]));
    expect(positions.every(({ x, y }) => Number.isFinite(x) && Number.isFinite(y))).toBe(true);
  });

  it("marks unscanned assets as neutral and never labels them compliant", () => {
    const card = mapCardAttributes({
      id: "si:si-1", kind: "si", si_id: "si-1", name: "Production",
      exposure: { targets: 4, scanned_targets: 0, unscanned_targets: 4, severity: {} },
    }, translate);
    expect(card.style.mapAccent).toBe("#7897b4");
    expect(card.style.mapMetrics).toBe("0 map.scanned · 4 map.unscanned");
    expect(card.style.mapSeverity).toBe("map.notScannedState");
    expect(String(card.style.mapSeverity)).not.toMatch(/compliant/i);
  });

  it("shows real critical and high findings with a bounded coverage ratio", () => {
    const card = mapCardAttributes({
      id: "zone:z1", kind: "zone", zone_id: "z1", name: "Public DMZ", zone_type: "dmz", cidr: "192.0.2.0/24",
      exposure: { targets: 3, scanned_targets: 7, unscanned_targets: 0, severity: { critical: 2, high: 1 } },
    }, translate);
    expect(card.style.mapAccent).toBe("#dc6b76");
    expect(card.style.mapRatio).toBe(1);
    expect(card.style.mapSeverity).toBe("map.criticalShort2   map.highShort1");
  });

  it("renders a scanned host as a populated compact card instead of an empty fallback shape", () => {
    const card = mapCardAttributes({
      id: "target:t1", kind: "host", target_id: "t1", name: "tls.example.test", value: "tls.example.test", ports: "443",
      exposure: { run_id: "run-1", status: "COMPLETED", finished_at: "2026-10-14T12:00:00Z", endpoints: [{ endpoint_id: "ep-1", hostname: "tls.example.test", ip_address: "192.0.2.5", port: 443, grade: "F", compliance_status: "non_compliant", highest_severity: "high", tls_versions: ["TLSv1.2"], cipher_suites: [], certificate: null, errors: [], untested_checks: [], tls_checks: [] }], severity: { high: 1 }, compliant: 0, non_compliant: 1, unevaluated: 0 },
    }, translate);
    expect(card.type).toBe("network-exposure-card");
    expect(card.style.size).toEqual([216, 96]);
    expect(card.style.mapSubtitle).toBe("tls.example.test · :443");
    expect(card.style.mapMetrics).toBe("1 map.endpoints");
    expect(card.style.mapSeverity).toBe("map.highShort1");
  });
});
