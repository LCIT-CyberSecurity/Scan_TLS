// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { TlsChecksPicker } from "../components/TlsChecksPicker";
import { I18nProvider } from "../i18n";
import { groupByFamily, isEnabled, recommendedSection, setEnabled, visibleChecks, withTlsSection, type TlsCheckSpec } from "../lib/tlsChecks";

const catalog: TlsCheckSpec[] = [
  { id: "hostname_san", family: "identity", recommended: true },
  { id: "tls_compression", family: "handshake", recommended: true },
  { id: "ecdhe_groups", family: "groups", recommended: false },
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
    expect(Object.keys(recommendedSection(catalog))).toEqual(["hostname_san", "tls_compression"]);
  });
  it("shows recommended, enabled and added checks only", () => {
    expect(visibleChecks(catalog, undefined, []).map((c) => c.id)).toEqual(["hostname_san", "tls_compression"]);
    expect(visibleChecks(catalog, { ecdhe_groups: { enabled: true } }, []).map((c) => c.id)).toContain("ecdhe_groups");
    expect(visibleChecks(catalog, undefined, ["ecdhe_groups"]).map((c) => c.id)).toContain("ecdhe_groups");
    expect(groupByFamily(catalog).map(([family]) => family)).toEqual(["identity", "handshake", "groups"]);
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
    expect(boxes).toHaveLength(2);
    boxes.forEach((b) => expect(b).not.toBeChecked());
    expect(screen.queryByText(/ECDHE groups/)).not.toBeInTheDocument();
    expect(screen.getByTestId("out").textContent).not.toContain("tls");
  });
  it("pre-checks nothing by itself: a new profile arrives with its recommended section", async () => {
    render(<Harness initial={{ checks: { tls: recommendedSection(catalog) } }} />);
    const boxes = await screen.findAllByRole("checkbox");
    boxes.forEach((b) => expect(b).toBeChecked());
    fireEvent.click(boxes[0]);
    await waitFor(() => expect(screen.getByTestId("out").textContent).not.toContain("hostname_san"));
    expect(screen.getByTestId("out").textContent).toContain("tls_compression");
  });
  it("adds another control through 'Add checks'", async () => {
    render(<Harness initial={{ checks: {} }} />);
    fireEvent.click(await screen.findByRole("button", { name: /add checks/i }));
    fireEvent.click(screen.getByRole("button", { name: /ECDHE groups/ }));
    const boxes = await screen.findAllByRole("checkbox");
    expect(boxes).toHaveLength(3);
    fireEvent.click(boxes[2]);
    await waitFor(() => expect(screen.getByTestId("out").textContent).toContain("ecdhe_groups"));
  });
});
