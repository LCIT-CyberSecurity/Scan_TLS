// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const apiMock = vi.hoisted(() => vi.fn());
vi.mock("../api/client", () => ({ api: apiMock }));

import { NetworkDiscovery } from "../components/NetworkDiscovery";
import { I18nProvider } from "../i18n";

describe("SNMP / LLDP discovery", () => {
  beforeEach(() => {
    apiMock.mockReset();
    apiMock.mockImplementation(async (path: string, options?: { method?: string }) => {
      if (path === "/map/snmp/config") return { enabled: true };
      if (path === "/targets") return [{ id: "target-1", name: "switch", value: "192.0.2.10", kind: "ip", ports: "", description: "", owner_id: null, tags: [], si_ids: [] }];
      if (path === "/map/snmp/discover" && !options?.method) return [];
      if (path === "/map/snmp/discover" && options?.method === "POST") return { id: "discovery-1", status: "queued", items: [] };
      if (path === "/map/snmp/discover/discovery-1") return { id: "discovery-1", status: "done", items: [{ target_id: "target-1", target: "192.0.2.10", address: "192.0.2.10", status: "observed", inventory_status: "new", system_name: "core-switch", sys_descr: "Ethernet switch", interfaces: [{ if_index: "1" }], neighbors: [{ local_port: "Gi1/0/1", chassis_id: "00:11:22:33:44:55", system_name: "edge-switch", inventory_status: "new" }] }] };
      if (path === "/map/snmp/discover/discovery-1/apply") return { applied_rows: 1, devices_created: 2, links_created: 1 };
      return [];
    });
  });

  it("selects authorized IP targets, previews observed LLDP results, and requires confirmation to apply", async () => {
    render(<I18nProvider initial="en"><NetworkDiscovery /></I18nProvider>);
    const select = await screen.findByLabelText("Authorized IP targets") as HTMLSelectElement;
    const option = await screen.findByRole("option", { name: /switch — 192\.0\.2\.10/ }) as HTMLOptionElement;
    option.selected = true;
    fireEvent.change(select);
    fireEvent.click(screen.getByRole("button", { name: "Run read-only discovery" }));

    expect(await screen.findByText("core-switch")).toBeInTheDocument();
    expect(screen.getByText(/edge-switch/)).toBeInTheDocument();
    expect(apiMock).toHaveBeenCalledWith("/map/snmp/discover", { method: "POST", body: { target_ids: ["target-1"], authorized: true, timeout_seconds: 2, concurrency: 5 } });
    fireEvent.click(screen.getByRole("button", { name: "Confirm map update" }));
    await waitFor(() => expect(apiMock).toHaveBeenCalledWith("/map/snmp/discover/discovery-1/apply", { method: "POST", body: { item_indexes: [0], confirm: true } }));
  });

  it("clearly reports that discovery stays disabled without server-side secrets", async () => {
    apiMock.mockImplementation(async (path: string) => path === "/map/snmp/config" ? { enabled: false } : path === "/targets" ? [] : []);
    render(<I18nProvider initial="en"><NetworkDiscovery /></I18nProvider>);
    expect(await screen.findByText(/SNMPv3 authPriv is not configured/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Run read-only discovery" })).not.toBeInTheDocument();
  });
});
