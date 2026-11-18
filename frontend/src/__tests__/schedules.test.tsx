// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { I18nProvider } from "../i18n";
import Schedules from "../pages/Schedules";

const calls: { path: string; method?: string; body?: Record<string, unknown> }[] = [];
const schedule = { id: "schedule-1", definition_id: "definition-1", owner_id: "user-1", kind: "daily", params: { time: "03:00" },
  timezone: "Europe/Paris", active: true, next_run_at: null, last_run_at: null, last_run: null };
vi.mock("../auth/AuthContext", () => ({ useAuth: () => ({ user: { id: "user-1" }, atLeast: () => false }) }));
vi.mock("../api/client", async (original) => ({
  ...(await original<typeof import("../api/client")>()),
  api: vi.fn(async (path: string, options: { method?: string; body?: Record<string, unknown> } = {}) => {
    calls.push({ path, method: options.method, body: options.body });
    if (path === "/schedules") return [schedule];
    if (path === "/scan-definitions") return [{ id: "definition-1", name: "Nightly scan" }];
    return schedule;
  }),
}));

afterEach(() => { cleanup(); calls.length = 0; });

it("lets the schedule owner edit timing while preserving definition and timezone", async () => {
  render(<MemoryRouter><I18nProvider><Schedules /></I18nProvider></MemoryRouter>);
  fireEvent.click(await screen.findByRole("button", { name: "Edit" }));
  fireEvent.change(screen.getByLabelText("Time"), { target: { value: "05:30" } });
  fireEvent.click(screen.getByRole("button", { name: "Save" }));
  await waitFor(() => expect(calls.some((call) => call.method === "PUT" && call.path === "/schedules/schedule-1")).toBe(true));
  expect(calls.find((call) => call.method === "PUT")?.body).toMatchObject({ definition_id: "definition-1", kind: "daily",
    params: { time: "05:30" }, timezone: "Europe/Paris", active: true });
});
