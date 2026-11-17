// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "../test-utils";
import { MemoryRouter } from "react-router-dom";
import Scans from "../pages/Scans";
import { I18nProvider } from "../i18n";

const calls: { path: string; method: string; body?: any }[] = []; // eslint-disable-line @typescript-eslint/no-explicit-any
vi.mock("../auth/AuthContext", () => ({ useAuth: () => ({ user: { id: "u1" }, atLeast: () => true }) }));
vi.mock("../api/client", async (original) => ({
  ...(await original<typeof import("../api/client")>()),
  api: vi.fn(async (path: string, options: { method?: string; body?: unknown } = {}) => {
    calls.push({ path, method: options.method ?? "GET", body: options.body });
    if (path === "/scan-runs" || path === "/scan-definitions" || path === "/targets" || path === "/target-groups" || path.startsWith("/policies") || path.startsWith("/profiles") || path === "/report-templates" || path === "/information-systems") return [];
    throw new Error(`unexpected request: ${path}`);
  }),
}));

afterEach(cleanup);
beforeEach(() => { calls.length = 0; });
const wrap = () => render(<MemoryRouter><I18nProvider initial="en"><Scans /></I18nProvider></MemoryRouter>);

describe("mail security scan options", () => {
  it("keeps the module off by default and exposes independent checks with the requested defaults", async () => {
    wrap();
    fireEvent.click(await screen.findByRole("button", { name: "New scan" }));
    const tls = screen.getByRole("checkbox", { name: "TLS" });
    const ipsec = screen.getByRole("checkbox", { name: "VPN IPsec / IKE" });
    expect(tls).toBeChecked();
    expect(ipsec).toBeChecked();
    fireEvent.click(ipsec);
    expect(tls).toBeChecked();
    expect(ipsec).not.toBeChecked();
    fireEvent.click(ipsec);
    expect(ipsec).toBeChecked();
    const section = screen.getByText("Additional checks");
    fireEvent.click(section);
    const enabled = screen.getByRole("checkbox", { name: "Mail security (disabled by default)" });
    expect(enabled).not.toBeChecked();
    fireEvent.click(enabled);
    expect(screen.getByRole("checkbox", { name: "SPF" })).toBeChecked();
    expect(screen.getByRole("checkbox", { name: "DMARC" })).toBeChecked();
    expect(screen.getByRole("checkbox", { name: "MTA-STS" })).toBeChecked();
    expect(screen.getByRole("checkbox", { name: "TLS-RPT" })).toBeChecked();
    expect(screen.getByRole("checkbox", { name: "DKIM" })).not.toBeChecked();
    expect(screen.getByRole("checkbox", { name: "DANE / TLSA" })).not.toBeChecked();
    fireEvent.click(screen.getByRole("checkbox", { name: "DKIM" }));
    fireEvent.change(screen.getByLabelText("Known DKIM selectors"), { target: { value: "selector1, selector2" } });
    await waitFor(() => expect(screen.getByLabelText("Known DKIM selectors")).toHaveValue("selector1, selector2"));
  });
});
