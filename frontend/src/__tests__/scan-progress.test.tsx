// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import type { Run } from "../api/types";
import { ScanProgress } from "../components/ScanProgress";
import { I18nProvider } from "../i18n";

afterEach(cleanup);
const plan = { targets: 3, ports: ["443,8443"], crypto: "standard", certificate: true, trust: true, public_store: true, private_stores: ["ACME PKI"], revocation: true, tls_checks: 12, policies: ["ANSSI"], formats: ["html", "csv"] };
const base = { id: "r", name: "n", status: "running", phase: "tls_scan", started_at: new Date(Date.now() - 65_000).toISOString(), progress: { hosts_total: 3, hosts_done: 1 }, cancel_requested: false, plan } as unknown as Run;
const wrap = (run: Run) => render(<I18nProvider><ScanProgress run={run} /></I18nProvider>);

describe("scan progress panel", () => {
  it("shows the steps, marks the current one and says what each step checks", () => {
    wrap(base);
    const panel = screen.getByRole("region", { name: "Scan progress" });
    const items = within(panel).getAllByRole("listitem");
    expect(items.map((i) => i.textContent)).toEqual(expect.arrayContaining([expect.stringContaining("Port discovery"), expect.stringContaining("TLS analysis"), expect.stringContaining("Reports")]));
    expect(items.filter((i) => i.getAttribute("aria-current") === "step")).toHaveLength(1);
    expect(items.find((i) => i.getAttribute("aria-current") === "step")).toHaveTextContent("TLS analysis");
    expect(panel).toHaveTextContent("chain trust: public authorities, ACME PKI");
    expect(panel).toHaveTextContent("revocation (OCSP/CRL)");
    expect(panel).toHaveTextContent("12 complementary check(s)");
    expect(panel).toHaveTextContent("Against ANSSI");
    expect(panel).toHaveTextContent("HTML, CSV");
    expect(within(panel).getByText("1/3 hosts analysed")).toBeInTheDocument();
    expect(within(panel).getByRole("progressbar")).toHaveAttribute("max", "3");
    expect(panel).toHaveTextContent(/Elapsed 1 ?min|Elapsed 1m|Elapsed 1:0/);
  });

  it("a queued scan has no current step and no fake progress", () => {
    wrap({ ...base, status: "queued", phase: "starting", started_at: null, progress: null } as unknown as Run);
    expect(screen.getByText("Waiting for a free worker…")).toBeInTheDocument();
    expect(screen.queryByRole("progressbar")).toBeNull();
    expect(screen.queryAllByRole("listitem").some((i) => i.getAttribute("aria-current") === "step")).toBe(false);
  });

  it("only shows what is really checked, and the post-quantum step when relevant", () => {
    wrap({ ...base, phase: "discovery", progress: null, plan: { ...plan, crypto: "pqc", trust: false, revocation: false, tls_checks: 0, private_stores: [] } } as unknown as Run);
    const panel = screen.getByRole("region", { name: "Scan progress" });
    expect(panel).toHaveTextContent("Post-quantum prerequisites");
    expect(panel).not.toHaveTextContent("chain trust");
    expect(panel).not.toHaveTextContent("revocation");
    expect(panel).not.toHaveTextContent("complementary");
    expect(screen.queryByRole("progressbar")).toBeNull();      // the total is only known once the TLS analysis starts
  });

  it("announces a cancellation request", () => {
    wrap({ ...base, cancel_requested: true });
    expect(screen.getByText(/Cancellation requested/)).toBeInTheDocument();
  });
});
