// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "../test-utils";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { I18nProvider } from "../i18n";
import Schedules from "../pages/Schedules";

const calls: { path: string; method?: string; body?: Record<string, unknown> }[] = [];
vi.mock("../auth/AuthContext", () => ({ useAuth: () => ({ user: { id: "operator-1" }, atLeast: () => true }) }));
vi.mock("../api/client", async (original) => ({
  ...(await original<typeof import("../api/client")>()),
  api: vi.fn(async (path: string, options: { method?: string; body?: Record<string, unknown> } = {}) => {
    calls.push({ path, method: options.method, body: options.body });
    if (path === "/schedules" || path === "/scan-definitions") return [];
    return undefined;
  }),
}));

afterEach(cleanup);

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
});
