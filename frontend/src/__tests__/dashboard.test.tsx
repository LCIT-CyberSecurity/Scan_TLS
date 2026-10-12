// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Posture, Trend } from "../api/types";
import { ComplianceBreakdown } from "../components/dashboard/ComplianceBreakdown";
import { ComplianceTrend } from "../components/dashboard/ComplianceTrend";
import { SecurityKpis } from "../components/dashboard/SecurityKpis";
import { Vigilance } from "../components/dashboard/Vigilance";
import { I18nProvider } from "../i18n";

afterEach(cleanup);
const wrap = (ui: React.ReactNode, lang: "en" | "fr" | "de" = "en") => render(<MemoryRouter><I18nProvider initial={lang}>{ui}</I18nProvider></MemoryRouter>);

const posture: Posture = {
  scans: 2, basis_run_ids: ["r1", "r2"], policies: [{ name: "P", version: 1 }, { name: "P", version: 2 }], mixed_policies: true, window_days: 30,
  endpoints: { total: 10, compliant: 6, non_compliant: 2, unevaluated: 2, rate: 75 },
  findings: { critical: { unique: 0, endpoints: 0 }, high: { unique: 2, endpoints: 3 }, occurrences: 3 },
  certificates: { expired: 1, expiring: 1, items: [{ subject: "CN=old.example.org", valid_until: "x", remaining_days: -3, endpoints: 2, run_id: "r1" }, { subject: "CN=soon.example.org", valid_until: "y", remaining_days: 12, endpoints: 1, run_id: "r2" }] },
  vigilance: [{ finding_id: "TLS_DEPRECATED_VERSION", title: "Deprecated TLS Version Enabled", category: "TLS Versions", severity: "high", endpoints: 3, run_id: "r1" },
              { finding_id: "ecdhe_groups", title: "ecdhe_groups", category: "complementary_check", severity: null, endpoints: 1, run_id: "r2" }],
};
const empty: Posture = { ...posture, scans: 0, mixed_policies: false, policies: [], endpoints: { total: 0, compliant: 0, non_compliant: 0, unevaluated: 0, rate: null },
  findings: { critical: { unique: 0, endpoints: 0 }, high: { unique: 0, endpoints: 0 }, occurrences: 0 }, certificates: { expired: 0, expiring: 0, items: [] }, vigilance: [] };

describe("SecurityKpis", () => {
  it("shows the four indicators with their detail and explanation", () => {
    wrap(<SecurityKpis posture={posture} />);
    expect(screen.getByText("75 %")).toBeInTheDocument();
    expect(screen.getByText("6 of 8 evaluated endpoints are compliant")).toBeInTheDocument();
    expect(screen.getByText("2 not evaluated")).toBeInTheDocument();
    expect(screen.getByText("Non-compliant endpoints").closest(".kpi")).toHaveTextContent("2");
    expect(screen.getByText("0 critical · 2 high")).toBeInTheDocument();
    expect(screen.getByText("1 expired · 1 expire within 30 days")).toBeInTheDocument();
    expect(screen.getByText("old.example.org")).toBeInTheDocument();
    expect(screen.getByText("expired 3 d ago")).toBeInTheDocument();
    // tooltips explain the method (and the unique/occurrence difference)
    expect(screen.getAllByRole("button").map((b) => b.getAttribute("data-tip")).join(" ")).toMatch(/÷ \(compliant \+ non-compliant\).*3 occurrences/s);
  });
  it("never invents a rate: nothing evaluated, or no data at all", () => {
    wrap(<SecurityKpis posture={empty} />);
    expect(screen.getByText("Not evaluated")).toBeInTheDocument();
    expect(screen.queryByText(/%/)).not.toBeInTheDocument();
    cleanup();
    wrap(<SecurityKpis posture={undefined} />);
    expect(screen.getAllByText("Not available").length).toBeGreaterThanOrEqual(3);
  });
  it("is translated", () => {
    wrap(<SecurityKpis posture={posture} />, "fr");
    expect(screen.getByText("Conformité TLS")).toBeInTheDocument();
    expect(screen.getByText("1 expirés · 1 expirent sous 30 jours")).toBeInTheDocument();
  });
});

describe("ComplianceBreakdown", () => {
  it("gives number and percentage for each part, and flags mixed policies", () => {
    wrap(<ComplianceBreakdown posture={posture} />);
    const legend = screen.getByRole("list");
    expect(within(legend).getByText("Compliant").closest("li")).toHaveTextContent(/60 %$/);
    expect(within(legend).getByText("Non-compliant").closest("li")).toHaveTextContent(/20 %$/);
    expect(within(legend).getByText("Not evaluated or partial").closest("li")).toHaveTextContent(/20 %$/);
    expect(screen.getByText(/Several policies or policy versions are combined here: P v1, P v2/)).toBeInTheDocument();
  });
  it("shows an explicit empty state", () => {
    wrap(<ComplianceBreakdown posture={empty} />);
    expect(screen.getByText("Run a scan to see your compliance here.")).toBeInTheDocument();
  });
});

const trend: Trend = {
  definition_id: "d1", definitions: [{ id: "d1", name: "Prod", runs: 3 }, { id: "d2", name: "Dev", runs: 1 }],
  points: [
    { run_id: "a", name: "Prod run 1", finished_at: "2026-10-01T10:00:00Z", rate: 50, compliant: 2, non_compliant: 2, evaluated: 4, total: 4, comparable: true },
    { run_id: "b", name: "Prod run 2", finished_at: "2026-10-02T10:00:00Z", rate: null, compliant: 0, non_compliant: 0, evaluated: 0, total: 4, comparable: true },
    { run_id: "c", name: "Prod run 3", finished_at: "2026-10-03T10:00:00Z", rate: 100, compliant: 5, non_compliant: 0, evaluated: 5, total: 7, comparable: false },
  ],
};
describe("ComplianceTrend", () => {
  it("plots rates between 0 and 100 %, links the points to their runs and leaves a gap for an unevaluated run", () => {
    const { container } = wrap(<ComplianceTrend trend={trend} onDefinition={() => {}} />);
    expect(container.querySelectorAll("circle")).toHaveLength(2);  // run b has no rate: no point
    expect(container.querySelectorAll("line.trend-line")).toHaveLength(0);  // and no line across the gap
    expect(screen.getByText("100 %", { selector: "text" })).toBeInTheDocument();
    const link = screen.getByRole("link", { name: /Prod run 3.*100 % · 5 compliant of 5 evaluated/ });
    expect(link).toHaveAttribute("href", "/scans/c");
    expect(container.querySelector("circle.trend-point--changed")).not.toBeNull();
    expect(screen.getByText("Hollow point: conditions changed since the previous run", { exact: false })).toBeInTheDocument();
  });
  it("shows the details of the hovered run and lets the user pick another scan", () => {
    const pick = vi.fn();
    wrap(<ComplianceTrend trend={trend} onDefinition={pick} />);
    fireEvent.mouseEnter(screen.getByRole("link", { name: /Prod run 1/ }));
    expect(screen.getByText("Prod run 1", { selector: "strong" })).toBeInTheDocument();
    expect(screen.getByText(/4 endpoints in the scan/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Scan"), { target: { value: "d2" } });
    expect(pick).toHaveBeenCalledWith("d2");
  });
  it("has an empty state", () => {
    wrap(<ComplianceTrend trend={{ definition_id: null, definitions: [], points: [] }} onDefinition={() => {}} />);
    expect(screen.getByText("Not enough finished scans yet.")).toBeInTheDocument();
  });
});

describe("Vigilance", () => {
  it("lists real anomalies with severity, distinct endpoints and a link, complementary checks by their label", () => {
    wrap(<Vigilance posture={posture} />);
    expect(screen.getByText("Deprecated TLS Version Enabled")).toBeInTheDocument();
    expect(screen.getByText("3 endpoints")).toBeInTheDocument();
    expect(screen.getByText("ECDHE groups")).toBeInTheDocument();
    expect(screen.getByText("Complementary check")).toBeInTheDocument();
    expect(screen.getAllByRole("link").map((l) => l.getAttribute("href"))).toEqual(["/scans/r1", "/scans/r2"]);
  });
  it("shows a sober empty state when nothing is found", () => {
    wrap(<Vigilance posture={empty} />);
    expect(screen.getByText("No anomaly found in the latest results.")).toBeInTheDocument();
  });
});
