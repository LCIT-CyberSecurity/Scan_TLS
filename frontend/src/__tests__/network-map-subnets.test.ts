import { describe, expect, it } from "vitest";
import type { MapNode } from "../api/types";
import { subnetFor } from "../components/network-map/NetworkMapFlow";

describe("network map subnet grouping", () => {
  it("uses an explicitly configured zone CIDR when it contains the host IP", () => {
    const zones: MapNode[] = [{ id: "zone:dmz", kind: "zone", name: "Public DMZ", cidr: "192.0.2.0/25" }];
    expect(subnetFor("192.0.2.64", zones)).toMatchObject({ label: "192.0.2.0/25", zone: zones[0] });
    expect(subnetFor("192.0.2.200", zones)).toMatchObject({ label: "192.0.2.0/24", zone: undefined });
  });

  it("groups IPv4 address assets into a visual /24 when no configured zone matches", () => {
    expect(subnetFor("198.51.100.17", [])).toMatchObject({ label: "198.51.100.0/24" });
    expect(subnetFor("web.example.test", [])).toBeNull();
  });
});
