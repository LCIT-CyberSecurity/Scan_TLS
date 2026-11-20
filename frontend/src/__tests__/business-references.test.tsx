// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "../test-utils";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactElement } from "react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { I18nProvider } from "../i18n";
import Schedules from "../pages/Schedules";
import Scans from "../pages/Scans";
import Targets from "../pages/Targets";

// LST-35: business references open their existing record (definition, target, group) without changing anything.
const role = vi.hoisted(() => ({ value: "OPERATOR", id: "owner-1" }));
const RANK: Record<string, number> = { AUDITOR: 1, USER: 2, OPERATOR: 3, ADMIN: 4 };
const calls = vi.hoisted(() => [] as { path: string; method?: string }[]);
const definition = { id: "def-1", name: "home scan", description: "", owner_id: "owner-1", profile_id: "p", control_type: "tls", enabled_controls: null,
  report_template_id: null, policy_mode: "strict_all", tags: [], si_ids: [], target_ids: ["t-1", "t-2", "t-3", "t-4", "t-5", "t-6"], group_ids: ["g-1"], policy_ids: [] };
const targetRows = ["t-1", "t-2", "t-3", "t-4", "t-5", "t-6"].map((id, i) => ({ id, value: `host${i + 1}.example`, name: i === 0 ? "Web front" : "", kind: "fqdn",
  ports: "443", tags: [], si_ids: [], owner_id: i === 1 ? "someone-else" : "owner-1", description: "" }));
const groupRows = [{ id: "g-1", name: "DMZ", description: "", target_ids: ["t-1"], tags: [], si_ids: [], owner_id: "owner-1" }];
const schedules = [
  { id: "s-1", task_type: "tls", definition_id: "def-1", owner_id: "owner-1", kind: "daily", params: {}, timezone: "Europe/Paris", active: true, next_run_at: null, last_run_at: null },
  { id: "s-2", task_type: "dns_discovery", task_config: { domain: "client.test", options: {} }, definition_id: null, owner_id: "owner-1", kind: "weekly", params: {}, timezone: "Europe/Paris", active: true, next_run_at: null, last_run_at: null },
  { id: "s-3", task_type: "tls", definition_id: "def-deleted", owner_id: "owner-1", kind: "daily", params: {}, timezone: "Europe/Paris", active: true, next_run_at: null, last_run_at: null },
];
vi.mock("../auth/AuthContext", () => ({ useAuth: () => ({ user: { id: role.id, role: role.value }, atLeast: (r: string) => RANK[role.value] >= RANK[r] }) }));
vi.mock("../api/client", async (original) => ({
  ...(await original<object>()),
  api: vi.fn(async (path: string, options: { method?: string } = {}) => {
    calls.push({ path, method: options.method });
    if (path === "/schedules") return schedules;
    if (path === "/scan-definitions") return [definition];
    if (path === "/targets") return targetRows;
    if (path === "/target-groups") return groupRows;
    return [];
  }),
}));

function Where() {
  const location = useLocation();
  return <p data-testid="where">{location.pathname + location.search}</p>;
}
function open(path: string, page: ReactElement) {
  return render(<I18nProvider initial="en"><MemoryRouter initialEntries={[path]}><Routes>
    <Route path="*" element={<>{page}<Where /></>} />
  </Routes></MemoryRouter></I18nProvider>);
}
const writes = () => calls.filter((call) => call.method && call.method !== "GET");

beforeEach(() => { role.value = "OPERATOR"; role.id = "owner-1"; calls.length = 0; });
afterEach(cleanup);

describe("Schedules: the task and its targets are links (LST-35)", () => {
  it("links the scan definition and each target or group to its record, without changing the schedule", async () => {
    open("/schedules", <Schedules />);
    const task = await screen.findByRole("link", { name: "home scan" });
    expect(task).toHaveAttribute("href", "/scans?tab=scans&definition=def-1");
    expect(task).toHaveClass("ref-link");
    const refs = within(await screen.findByLabelText("Targets")).getAllByRole("link");
    expect(refs.map((link) => [link.textContent, link.getAttribute("href")])).toEqual([
      ["Web front", "/targets?target=t-1"], ["host2.example", "/targets?target=t-2"], ["host3.example", "/targets?target=t-3"],
      ["host4.example", "/targets?target=t-4"], ["host5.example", "/targets?target=t-5"], ["+2 more", "/scans?tab=scans&definition=def-1"],
    ]);
    fireEvent.click(refs[0]);
    expect(screen.getByTestId("where")).toHaveTextContent("/targets?target=t-1");
    expect(writes()).toHaveLength(0);                                           // a click never writes anything
  });

  it("keeps a DNS discovery as text (no other screen) and flags a deleted definition without a link", async () => {
    open("/schedules", <Schedules />);
    expect(await screen.findByText("DNS discovery · client.test")).not.toHaveAttribute("href");
    expect(screen.queryByRole("link", { name: /client\.test/ })).toBeNull();
    expect(await screen.findByText("(scan definition deleted or not accessible)")).toBeInTheDocument();
  });
});

describe("Scans: ?definition= opens the existing edit dialog (LST-35)", () => {
  it("opens the definition, and closing it drops the parameter", async () => {
    open("/scans?tab=scans&definition=def-1", <Scans />);
    expect(await screen.findByRole("dialog", { name: "Edit scan definition" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.getByTestId("where")).toHaveTextContent(/^\/scans\?tab=scans$/));
    expect(writes()).toHaveLength(0);
  });

  it("explains a deleted or inaccessible definition, and a definition the user may not edit", async () => {
    open("/scans?tab=scans&definition=def-deleted", <Scans />);
    expect(await screen.findByText("This scan definition no longer exists or is not accessible to you.")).toBeInTheDocument();
    cleanup();
    role.value = "USER"; role.id = "another-user";
    open("/scans?tab=scans&definition=def-1", <Scans />);
    expect(await screen.findByText("Only its owner or an operator can edit this scan definition.")).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).toBeNull();
  });
});

describe("Targets: ?target= / ?group= open the existing record (LST-35)", () => {
  it("opens the target the user may edit, and drops the parameter on close", async () => {
    role.value = "USER";
    open("/targets?target=t-1", <Targets />);
    expect(await screen.findByRole("dialog", { name: "Edit target" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.getByTestId("where")).toHaveTextContent(/^\/targets$/));
  });

  it("shows a target owned by someone else read-only, filtered, and explains a missing one", async () => {
    role.value = "USER";
    open("/targets?target=t-2", <Targets />);
    expect(await screen.findByText(/The list is filtered on this target/)).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByLabelText("Search")).toHaveValue("host2.example");
    cleanup();
    open("/targets?target=t-unknown", <Targets />);
    expect(await screen.findByText("This target no longer exists or is not accessible to you.")).toBeInTheDocument();
  });

  it("opens a group on the groups tab", async () => {
    open("/targets?group=g-1", <Targets />);
    expect(await screen.findByRole("dialog", { name: "Edit group" })).toBeInTheDocument();
  });
});
