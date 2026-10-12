// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { TlsChecksPicker } from "../components/TlsChecksPicker";
import { I18nProvider } from "../i18n";
import { getOption, groupByFamily, isEnabled, parsePorts, recommendedSection, setEnabled, setOption, visibleChecks, withTlsSection, type TlsCheckSpec } from "../lib/tlsChecks";

const catalog: TlsCheckSpec[] = [
  { id: "hostname_san", family: "identity", recommended: true },
  { id: "tls_compression", family: "handshake", recommended: true },
  { id: "ecdhe_groups", family: "groups", recommended: false },
  { id: "early_data", family: "sessions", recommended: true, options: [{ name: "probe", kind: "bool", default: false, min: null, max: null }, { name: "ticket_wait_seconds", kind: "int", default: 3, min: 0, max: 10 }] },
  { id: "starttls_imap", family: "protocols", recommended: true, options: [{ name: "ports", kind: "ports", default: [], min: null, max: null }] },
];
vi.mock("../api/client", () => ({ api: vi.fn(async () => catalog) }));
afterEach(cleanup);

describe("tls checks helpers", () => {
  it("never enables anything on a profile without the section (historical behaviour)", () => {
    expect(isEnabled(undefined, "hostname_san")).toBe(false);
    expect(isEnabled({}, "hostname_san")).toBe(false);
    expect(isEnabled({ hostname_san: { enabled: false } }, "hostname_san")).toBe(false);
  });
  it("recommends only the recommended checks, for new profiles", () => {
    expect(Object.keys(recommendedSection(catalog))).toEqual(["hostname_san", "tls_compression", "early_data", "starttls_imap"]);
  });
  it("shows recommended, enabled and added checks only", () => {
    expect(visibleChecks(catalog, undefined, []).map((c) => c.id)).toEqual(["hostname_san", "tls_compression", "early_data", "starttls_imap"]);
    expect(visibleChecks(catalog, { ecdhe_groups: { enabled: true } }, []).map((c) => c.id)).toContain("ecdhe_groups");
    expect(visibleChecks(catalog, undefined, ["ecdhe_groups"]).map((c) => c.id)).toContain("ecdhe_groups");
    expect(groupByFamily(catalog).map(([family]) => family)).toEqual(["identity", "handshake", "groups", "sessions", "protocols"]);
  });
  it("removes the section when nothing is left and keeps the other checks sections", () => {
    const content = { scan: {}, checks: { certificate: { enabled: true } } };
    const on = withTlsSection(content, setEnabled(undefined, "hostname_san", true));
    expect((on.checks as Record<string, unknown>).tls).toEqual({ hostname_san: { enabled: true } });
    expect((on.checks as Record<string, unknown>).certificate).toEqual({ enabled: true });
    const off = withTlsSection(on, setEnabled({ hostname_san: { enabled: true } }, "hostname_san", false));
    expect(off.checks).toEqual({ certificate: { enabled: true } });
  });
});

function Harness({ initial }: { initial: Record<string, unknown> }) {
  const [value, setValue] = useState(initial);
  return <I18nProvider initial="en"><TlsChecksPicker value={value} onChange={setValue} /><pre data-testid="out">{JSON.stringify(value)}</pre></I18nProvider>;
}

describe("TlsChecksPicker", () => {
  it("lists the recommended checks unchecked for an existing profile, and hides the others behind 'Add checks'", async () => {
    render(<Harness initial={{ scan: {}, checks: { certificate: { enabled: true } } }} />);
    const boxes = await screen.findAllByRole("checkbox");
    expect(boxes).toHaveLength(4);
    boxes.forEach((b) => expect(b).not.toBeChecked());
    expect(screen.queryByText(/ECDHE groups/)).not.toBeInTheDocument();
    expect(screen.getByTestId("out").textContent).not.toContain("tls");
  });
  it("pre-checks nothing by itself: a new profile arrives with its recommended section", async () => {
    render(<Harness initial={{ checks: { tls: recommendedSection(catalog) } }} />);
    const boxes = (await screen.findAllByRole("checkbox")).filter((b) => !b.closest("details"));  // the checks, not their option fields
    boxes.forEach((b) => expect(b).toBeChecked());
    fireEvent.click(boxes[0]);
    await waitFor(() => expect(screen.getByTestId("out").textContent).not.toContain("hostname_san"));
    expect(screen.getByTestId("out").textContent).toContain("tls_compression");
  });
  it("adds another control through 'Add checks'", async () => {
    render(<Harness initial={{ checks: {} }} />);
    fireEvent.click(await screen.findByRole("button", { name: /add checks/i }));
    fireEvent.click(screen.getByRole("button", { name: /ECDHE groups/ }));
    const boxes = (await screen.findAllByRole("checkbox")).filter((b) => !b.closest("details"));
    expect(boxes).toHaveLength(5);
    fireEvent.click(boxes[2]);  // groups come third in catalogue order
    await waitFor(() => expect(screen.getByTestId("out").textContent).toContain("ecdhe_groups"));
  });
});

describe("technical options of a check", () => {
  it("reads and writes options without disabling the check, and removes them with undefined", () => {
    const on = setEnabled(undefined, "early_data", true);
    const withProbe = setOption(on, "early_data", "probe", true);
    expect(withProbe).toEqual({ early_data: { enabled: true, probe: true } });
    expect(getOption(withProbe, "early_data", "probe")).toBe(true);
    expect(setOption(withProbe, "early_data", "probe", undefined)).toEqual({ early_data: { enabled: true } });
    expect(setOption({ client_auth: true }, "client_auth", "x", 1)).toEqual({ client_auth: { enabled: true, x: 1 } });
  });
  it("parses port lists strictly", () => {
    expect(parsePorts("143, 1143")).toEqual([143, 1143]);
    expect(parsePorts("  ")).toBeUndefined();
    for (const bad of ["0", "70000", "143 143", "abc", "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17"]) expect(parsePorts(bad)).toBeNull();
  });
  it("shows advanced options only for an enabled check and writes them to the profile", async () => {
    render(<Harness initial={{ checks: { tls: { early_data: { enabled: true }, starttls_imap: { enabled: true } } } }} />);
    const summaries = await screen.findAllByText("Advanced options");
    expect(summaries).toHaveLength(2);
    fireEvent.click(await screen.findByLabelText("Deep probe (sends an empty line as early data)"));
    await waitFor(() => expect(screen.getByTestId("out").textContent).toContain('"early_data":{"enabled":true,"probe":true}'));
    fireEvent.change(screen.getByLabelText("Ports (comma separated, empty = standard)"), { target: { value: "143, 1143" } });
    await waitFor(() => expect(screen.getByTestId("out").textContent).toContain('"ports":[143,1143]'));
    fireEvent.change(screen.getByLabelText("Ports (comma separated, empty = standard)"), { target: { value: "" } });
    await waitFor(() => expect(screen.getByTestId("out").textContent).not.toContain("ports"));
  });
  it("offers no option editor for a disabled check", async () => {
    render(<Harness initial={{ checks: { certificate: { enabled: true } } }} />);
    await screen.findAllByRole("checkbox");
    expect(screen.queryByText("Advanced options")).not.toBeInTheDocument();
  });
});
