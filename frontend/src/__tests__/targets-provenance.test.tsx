// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Targets from "../pages/Targets";
import { I18nProvider } from "../i18n";

const calls: { path: string; params?: Record<string, string> }[] = [];
const dns = (created: boolean) => ({ domains: ["client.test"], methods: ["axfr", "dns"], created, first_seen: "2026-10-01T10:00:00Z", last_seen: "2026-10-12T10:00:00Z", discovery_id: "d1" });
const target = (value: string, extra: Record<string, unknown> = {}) => ({ id: value, name: "", value, kind: "fqdn", ports: "", description: "", owner_id: null, tags: [], si_ids: [], dns: null, ...extra });
vi.mock("../auth/AuthContext", () => ({ useAuth: () => ({ user: { id: "u1" }, atLeast: () => true }) }));
vi.mock("../api/client", async (original) => ({
  ...(await original<typeof import("../api/client")>()),
  api: vi.fn(async (path: string, options: { params?: Record<string, string> } = {}) => {
    calls.push({ path, params: options.params });
    if (path === "/targets") {
      const all = [target("manual.example.org"), target("srv01.client.test", { tags: ["Découverte DNS"], dns: dns(true) }), target("vpn.client.test", { dns: dns(false) })];
      return options.params?.provenance === "dns" || options.params?.discovery ? all.filter((t) => t.dns) : all;
    }
    if (path.endsWith("/dns")) return { ips: [{ ip: "10.0.0.10" }], cnames: [{ name: "alias.client.test" }], sources: [], provenance: dns(true) };
    return [];
  }),
}));

afterEach(cleanup);
beforeEach(() => { calls.length = 0; });

describe("Targets: DNS provenance", () => {
  it("marks the targets a discovery saw, tells created from enriched, and filters on the provenance", async () => {
    render(<I18nProvider><Targets /></I18nProvider>);
    await screen.findByText("manual.example.org");
    expect(screen.getAllByRole("button", { name: /DNS provenance/ })).toHaveLength(2);          // nothing added to the manual target
    expect(screen.getByRole("button", { name: "DNS provenance srv01.client.test" })).toHaveAttribute("title", expect.stringContaining("Created by a DNS discovery"));
    expect(screen.getByRole("button", { name: "DNS provenance vpn.client.test" })).toHaveAttribute("title", expect.stringContaining("Enriched by a DNS discovery"));
    fireEvent.change(screen.getByLabelText("Origin"), { target: { value: "dns" } });
    await waitFor(() => expect(screen.queryByText("manual.example.org")).toBeNull());
    expect(calls.at(-1)!.params).toMatchObject({ provenance: "dns" });
    fireEvent.click(screen.getByRole("button", { name: "DNS provenance srv01.client.test" }));
    expect(await screen.findByText("alias.client.test")).toBeInTheDocument();
    expect(screen.getByText("axfr, dns")).toBeInTheDocument();
    expect(screen.getByText(/not proof that the host is reachable/)).toBeInTheDocument();
  });
});
