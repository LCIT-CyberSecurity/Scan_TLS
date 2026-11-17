// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "../test-utils";
import { MemoryRouter } from "react-router-dom";
import { I18nProvider } from "../i18n";
import type { Run } from "../api/types";
import Reports from "../pages/Reports";
vi.mock("../auth/AuthContext", () => ({ useAuth: () => ({ atLeast: () => true }) }));

const { apiMock } = vi.hoisted(() => ({ apiMock: vi.fn() }));
vi.mock("../api/client", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api/client")>()),
  api: apiMock,
}));

afterEach(() => { cleanup(); apiMock.mockReset(); });

const run: Run = {
  id: "run-1", name: "Home Scan", definition_id: "def-1", schedule_id: null, initiated_by: "admin",
  status: "completed", phase: "completed", queued_at: "2026-11-17T10:00:00Z", started_at: null,
  finished_at: "2026-11-17T10:01:00Z", duration_seconds: 60, cancel_requested: false, error: "",
  progress: null, summary: { non_compliant_endpoints: 0 }, policy_versions: [], reports: [
    { format: "html", size: 1000 }, { format: "csv", size: 200 },
  ],
};

describe("Reports page", () => {
  it("opens HTML reports inline in a new tab while keeping other formats as downloads", async () => {
    apiMock.mockImplementation(async (path: string) => path === "/scan-runs" ? [run] : []);
    render(<MemoryRouter><I18nProvider><Reports /></I18nProvider></MemoryRouter>);

    const html = await screen.findByRole("link", { name: "HTML" });
    expect(html).toHaveAttribute("href", "/api/scan-runs/run-1/reports/html?inline=true");
    expect(html).toHaveAttribute("target", "_blank");

    const csv = screen.getByRole("link", { name: "CSV" });
    expect(csv).toHaveAttribute("href", "/api/scan-runs/run-1/reports/csv");
    expect(csv).not.toHaveAttribute("target");
  });

  it("filters reports by format and preserves legacy single-report links", async () => {
    apiMock.mockImplementation(async (path: string) => path === "/scan-runs" ? [run] : []);
    render(<MemoryRouter initialEntries={["/scans?tab=reports&run_id=run-1&format=html"]}><I18nProvider initial="en"><Reports embedded /></I18nProvider></MemoryRouter>);
    expect(await screen.findByRole("link", { name: "HTML" })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "CSV" })).toBeNull();
  });
});
