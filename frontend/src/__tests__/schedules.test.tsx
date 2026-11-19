// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "../test-utils";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { I18nProvider } from "../i18n";
import Schedules from "../pages/Schedules";

const calls: { path: string; method?: string; body?: Record<string, unknown> }[] = [];
let scheduleRows: Record<string, unknown>[] = [];
vi.mock("../auth/AuthContext", () => ({ useAuth: () => ({ user: { id: "operator-1" }, atLeast: () => true }) }));
vi.mock("../api/client", async (original) => ({
  ...(await original<typeof import("../api/client")>()),
  api: vi.fn(async (path: string, options: { method?: string; body?: Record<string, unknown> } = {}) => {
    calls.push({ path, method: options.method, body: options.body });
    if (path === "/schedules") return scheduleRows;
    if (path === "/scan-definitions") return [{ id: "definition-1", name: "Nightly scan" }];
    if (path.startsWith("/schedules/")) return scheduleRows.find((row) => row.id === path.split("/").at(-1));
    return undefined;
  }),
}));

afterEach(() => { cleanup(); scheduleRows = []; calls.length = 0; });

describe("DNS schedules", () => {
  it("requires explicit authorization and sends the existing discovery options to the shared scheduler", async () => {
    calls.length = 0;
    render(<MemoryRouter><I18nProvider><Schedules /></I18nProvider></MemoryRouter>);
    const newSchedule = await screen.findByRole("button", { name: "New schedule" });
    await waitFor(() => expect(newSchedule).toBeEnabled());
    fireEvent.click(newSchedule);
    fireEvent.change(screen.getByLabelText("Task type"), { target: { value: "dns_discovery" } });
    fireEvent.change(screen.getByLabelText("Domain or zone"), { target: { value: "client.test" } });
    const save = screen.getByRole("button", { name: "Save" });
    expect(save).toBeDisabled();
    fireEvent.click(screen.getByLabelText(/I confirm that I am authorised/));
    expect(save).toBeEnabled();
    fireEvent.click(save);
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/schedules")).toBe(true));
    const request = calls.find((c) => c.method === "POST" && c.path === "/schedules")!.body!;
    expect(request).toMatchObject({ task_type: "dns_discovery", domain: "client.test", authorized: true,
      dns_options: { mode: "fast", methods: ["dns", "axfr"], timeout_seconds: 5, concurrency: 20 },
      kind: "daily", params: { time: "03:00" } });
    expect(request).not.toHaveProperty("definition_id");
  });

  it("lets an owner edit an existing TLS schedule without losing its definition or timezone", async () => {
    scheduleRows = [{ id: "schedule-1", task_type: "tls", task_config: null, definition_id: "definition-1", owner_id: "operator-1",
      kind: "daily", params: { time: "03:00" }, timezone: "Europe/Paris", active: true, next_run_at: null, last_run_at: null, last_run: null }];
    render(<MemoryRouter><I18nProvider><Schedules /></I18nProvider></MemoryRouter>);
    fireEvent.click(await screen.findByRole("button", { name: "Edit" }));
    fireEvent.change(screen.getByLabelText("Time"), { target: { value: "05:30" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(calls.some((call) => call.method === "PUT" && call.path === "/schedules/schedule-1")).toBe(true));
    expect(calls.find((call) => call.method === "PUT")?.body).toMatchObject({ task_type: "tls", definition_id: "definition-1",
      kind: "daily", params: { time: "05:30" }, timezone: "Europe/Paris", active: true });
  });

  it("lets an operator edit a DNS schedule and requires fresh authorization", async () => {
    scheduleRows = [{ id: "schedule-dns", task_type: "dns_discovery", task_config: { domain: "client.test", options: {
      mode: "advanced", methods: ["dns", "axfr"], dictionary: "extended", timeout_seconds: 7, concurrency: 8,
      max_duration_seconds: 120, axfr_servers: [], reverse_addresses: [], custom_words: [],
    } }, definition_id: null, owner_id: "operator-1", kind: "weekly", params: { time: "04:15", weekday: 2 },
      timezone: "UTC", active: true, next_run_at: null, last_run_at: null, last_run: null }];
    render(<MemoryRouter><I18nProvider><Schedules /></I18nProvider></MemoryRouter>);
    fireEvent.click(await screen.findByRole("button", { name: "Edit" }));
    expect(screen.getByLabelText("Domain or zone")).toHaveValue("client.test");
    const save = screen.getByRole("button", { name: "Save" });
    expect(save).toBeDisabled();
    fireEvent.click(screen.getByLabelText(/I confirm that I am authorised/));
    fireEvent.change(screen.getByLabelText("Time"), { target: { value: "06:00" } });
    fireEvent.click(save);
    await waitFor(() => expect(calls.some((call) => call.method === "PUT" && call.path === "/schedules/schedule-dns")).toBe(true));
    expect(calls.find((call) => call.method === "PUT")?.body).toMatchObject({ task_type: "dns_discovery", domain: "client.test",
      authorized: true, dns_options: { mode: "advanced", methods: ["dns", "axfr"], dictionary: "extended",
        timeout_seconds: 7, concurrency: 8, max_duration_seconds: 120 }, kind: "weekly", params: { time: "06:00", weekday: 2 } });
  });
});
