// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen } from "../test-utils";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { I18nProvider } from "../i18n";
import RunDetail from "../pages/RunDetail";

const run = {
  id: "r1", name: "home scan", status: "completed", control_type: "tls", queued_at: "2026-11-19T17:46:00Z", duration_seconds: 42,
  initiated_by: "u", summary: null, reports: [], endpoints: [], findings: [], policy_versions: [], trust_stores: [], skipped_hosts: [],
};
vi.mock("../auth/AuthContext", () => ({ useAuth: () => ({ user: { id: "u", role: "USER" }, atLeast: (role: string) => role !== "OPERATOR" && role !== "ADMIN" }) }));
vi.mock("../api/client", async (original) => ({ ...(await original<object>()), api: vi.fn(async () => run) }));

function Where() {
  const location = useLocation();
  return <p data-testid="where">{location.pathname + location.search}</p>;
}

function openRun(entries: string[]) {
  return render(<I18nProvider initial="en"><MemoryRouter initialEntries={entries} initialIndex={entries.length - 1}><Routes>
    <Route path="/scans" element={<Where />} />
    <Route path="/scans/:id" element={<RunDetail />} />
  </Routes></MemoryRouter></I18nProvider>);
}

afterEach(cleanup);

describe("scan detail back button (LST-32)", () => {
  it("returns to the page the scan was opened from, with its tab and filters", async () => {
    openRun(["/scans?tab=reports&format=csv", "/scans/r1"]);
    fireEvent.click(await screen.findByRole("button", { name: "Back" }));
    expect(await screen.findByTestId("where")).toHaveTextContent("/scans?tab=reports&format=csv");
  });

  it("goes to the scan history when the scan was opened directly", async () => {
    openRun(["/scans/r1"]);
    fireEvent.click(await screen.findByRole("button", { name: "Back" }));
    expect(await screen.findByTestId("where")).toHaveTextContent("/scans?tab=history");
  });
});
