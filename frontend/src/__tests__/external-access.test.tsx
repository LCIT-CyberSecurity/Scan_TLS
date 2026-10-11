// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ExternalAccessSwitches, KeyDialog, ServiceAccess } from "../components/ExternalAccess";
import { I18nProvider } from "../i18n";

afterEach(cleanup);
const wrap = (ui: React.ReactNode) => render(<I18nProvider>{ui}</I18nProvider>);
const key = { active: false, prefix: null, created_at: null, expires_at: null, last_used_at: null };

describe("global switches", () => {
  it("shows both services off and reports a toggle", () => {
    const onToggle = vi.fn();
    wrap(<ExternalAccessSwitches state={{ api_enabled: false, mcp_enabled: false }} onToggle={onToggle} />);
    const switches = screen.getAllByRole("switch");
    expect(switches).toHaveLength(2);
    switches.forEach((s) => expect(s).not.toBeChecked());
    fireEvent.click(switches[0]);
    expect(onToggle).toHaveBeenCalledWith("api", true);
    fireEvent.click(switches[1]);
    expect(onToggle).toHaveBeenCalledWith("mcp", true);
  });
  it("reflects an enabled service", () => {
    wrap(<ExternalAccessSwitches state={{ api_enabled: true, mcp_enabled: false }} onToggle={() => undefined} />);
    expect(screen.getAllByRole("switch")[0]).toBeChecked();
    expect(screen.getAllByRole("switch")[1]).not.toBeChecked();
  });
});

describe("key management", () => {
  it("offers no usable button when the account is not authorised, and says why", () => {
    wrap(<ServiceAccess service="api" state={{ global_enabled: true, allowed: false, key }} onGenerate={() => undefined} onRevoke={() => undefined} />);
    expect(screen.getByRole("button", { name: /generate/i })).toBeDisabled();
    expect(screen.getByText(/not authorised to use this service/i)).toBeInTheDocument();
  });
  it("explains a globally disabled service", () => {
    wrap(<ServiceAccess service="mcp" state={{ global_enabled: false, allowed: true, key }} onGenerate={() => undefined} onRevoke={() => undefined} />);
    expect(screen.getByRole("button", { name: /generate/i })).toBeDisabled();
    expect(screen.getByText(/currently disabled by the administrator/i)).toBeInTheDocument();
  });
  it("generates, regenerates and revokes when allowed", () => {
    const onGenerate = vi.fn(), onRevoke = vi.fn();
    const { rerender } = wrap(<ServiceAccess service="api" state={{ global_enabled: true, allowed: true, key }} onGenerate={onGenerate} onRevoke={onRevoke} />);
    fireEvent.click(screen.getByRole("button", { name: /generate a key/i }));
    expect(onGenerate).toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: /revoke/i })).toBeNull();
    rerender(<I18nProvider><ServiceAccess service="api" state={{ global_enabled: true, allowed: true, key: { ...key, active: true, prefix: "tls_scan_pat_ab12cd", expires_at: "2027-01-01T00:00:00Z" } }} onGenerate={onGenerate} onRevoke={onRevoke} /></I18nProvider>);
    expect(screen.getByText(/tls_scan_pat_ab12cd/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /regenerate/i })).toBeEnabled();
    fireEvent.click(screen.getByRole("button", { name: /^revoke$/i }));
    expect(onRevoke).toHaveBeenCalled();
  });
  it("shows a new key once, with a warning and a copy button", () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, { clipboard: { writeText } });
    const onClose = vi.fn();
    wrap(<KeyDialog secret="tls_scan_pat_example-not-a-real-secret" onClose={onClose} />);
    expect(screen.getByTestId("secret")).toHaveTextContent("tls_scan_pat_example-not-a-real-secret");
    expect(screen.getByText(/shown only once/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /copy/i }));
    expect(writeText).toHaveBeenCalledWith("tls_scan_pat_example-not-a-real-secret");
  });
});
