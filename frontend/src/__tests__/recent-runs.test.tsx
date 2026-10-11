// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it } from "vitest";
import type { Run } from "../api/types";
import { RecentRuns } from "../components/RecentRuns";
import { I18nProvider } from "../i18n";

afterEach(cleanup);
const run = (id: string, definition: string | null, queued: string): Run => ({ id, name: "Weekly web", definition_id: definition, status: "completed", queued_at: queued, duration_seconds: 12, summary: { non_compliant_endpoints: 2 } } as unknown as Run);

describe("recent scans", () => {
  it("shows one row per scan with the latest run, and a chevron unfolds the history", () => {
    render(<MemoryRouter><I18nProvider><RecentRuns runs={[run("a", "d1", "2026-01-01T10:00:00Z"), run("b", "d1", "2026-01-03T10:00:00Z"), run("c", "d2", "2026-01-02T10:00:00Z")]} /></I18nProvider></MemoryRouter>);
    expect(screen.getAllByRole("link")).toHaveLength(2);
    const chevrons = screen.getAllByRole("button", { expanded: false });
    expect(chevrons).toHaveLength(1);                       // only the scan that was run several times can unfold
    fireEvent.click(chevrons[0]);
    expect(screen.getAllByRole("link")).toHaveLength(4);    // 2 scans + the 2 runs of the unfolded one
    expect(screen.getByRole("button", { expanded: true })).toBeInTheDocument();
  });
});
