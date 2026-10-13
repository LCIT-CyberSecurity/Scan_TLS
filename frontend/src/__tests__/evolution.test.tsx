// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Evolution as Data, EvolutionRun } from "../api/types";
import { Evolution } from "../components/dashboard/Evolution";
import { I18nProvider } from "../i18n";

afterEach(cleanup);
const run = (id: string, day: string, findings: Partial<EvolutionRun["findings"]> = {}): EvolutionRun => ({ run_id: id, name: id, finished_at: `${day}T10:00:00Z`, endpoints: 4, compliant: 2, non_compliant: 2, rate: 50,
  findings: { critical: 0, high: 0, medium: 0, low: 0, ...findings } });
const a = run("r1", "2026-09-20", { critical: 1, high: 4, medium: 2 }), b = run("r2", "2026-10-10", { critical: 0, high: 6, medium: 2 });
const ok: Data = { definition_id: "d", date_from: "2026-09-20", date_to: "2026-10-12", status: "ok", from_run: a, to_run: b, series: [a, b],
  comparison: { counts: { new: 3, fixed: 2, persistent: 5, not_retested: 1 }, warnings: ["scope_differs"],
    new: [{ finding_id: "WEAK_CIPHER", title: "Weak cipher suites", severity: "high", endpoints: 2 }], fixed: [{ finding_id: "EXPIRED", title: "Expired certificate", severity: "critical", endpoints: 1 }], persistent: [],
    endpoints_added: 2, endpoints_removed: 1, certificate_changes: [{ endpoint_id: "10.0.0.1:443/tcp", before: "CN=old", after: "CN=new" }], compliance: { improved: 1, degraded: 0 } } };
const wrap = (data: Data | undefined, onRange = vi.fn()) => render(<MemoryRouter><I18nProvider><Evolution data={data} from="2026-09-20" to="2026-10-12" onRange={onRange} /></I18nProvider></MemoryRouter>);

describe("dashboard evolution between two dates", () => {
  it("shows the counts, the per-severity change, the main new and fixed findings and the caution about the scans", () => {
    wrap(ok);
    const tiles = document.querySelector(".evo-tiles") as HTMLElement;
    expect(tiles).toHaveTextContent("3New");
    expect(tiles).toHaveTextContent("2Fixed");
    expect(tiles).toHaveTextContent("5Persistent");
    expect(tiles).toHaveTextContent("1Not retested");
    const table = screen.getByRole("table", { name: "Findings per severity" });
    const rows = within(table).getAllByRole("row").slice(1).map((r) => r.textContent);
    expect(rows[0]).toContain("Critical");
    expect(rows[0]).toMatch(/Critical10-1$/);        // 1 -> 0: improved
    expect(rows[1]).toMatch(/High46\+2$/);           // 4 -> 6: worse
    expect(screen.getByText("Weak cipher suites")).toBeInTheDocument();
    expect(screen.getByText("Expired certificate")).toBeInTheDocument();
    expect(screen.getByText("The targets differ between the two scans.")).toBeInTheDocument();
    expect(screen.getByText(/Endpoints: \+2 \/ -1/)).toBeInTheDocument();
    expect(screen.getByText(/1 improved, 0 degraded/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open the detailed comparison" })).toHaveAttribute("href", "/scans/r2?compare=r1");
    expect(screen.getByRole("img", { name: "Findings per scan (occurrences by severity)" })).toBeInTheDocument();
  });

  it("lets the dates be changed and explains the empty cases", () => {
    const onRange = vi.fn();
    wrap(ok, onRange);
    fireEvent.change(screen.getByLabelText("From"), { target: { value: "2026-09-01" } });
    expect(onRange).toHaveBeenCalledWith("2026-09-01", "2026-10-12");
    fireEvent.change(screen.getByLabelText("To"), { target: { value: "2026-10-01" } });
    expect(onRange).toHaveBeenLastCalledWith("2026-09-20", "2026-10-01");
    cleanup();
    wrap({ ...ok, status: "no_runs", from_run: null, to_run: null, comparison: null, series: [] });
    expect(screen.getByText("No finished scan of this scan definition up to that date.")).toBeInTheDocument();
    cleanup();
    wrap({ ...ok, status: "single_run", from_run: null, comparison: null, series: [b] });
    expect(screen.getByText(/Only one scan in this period/)).toBeInTheDocument();
    cleanup();
    wrap({ ...ok, status: "invalid_range", from_run: null, to_run: null, comparison: null, series: [] });
    expect(screen.getByText("The start date must not be after the end date.")).toBeInTheDocument();
  });
});
