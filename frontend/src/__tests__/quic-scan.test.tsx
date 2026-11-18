// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "../test-utils";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import Scans from "../pages/Scans";
import { I18nProvider } from "../i18n";

const { api } = vi.hoisted(() => ({ api: vi.fn() }));
api.mockImplementation(async (path: string) => {
  if (path === "/profiles?technology=generic") return [{ id: "profile-1", name: "QUIC profile", description: "", technology: "generic", archived: false,
    versions: [{ id: "v1", version: 1, status: "published", published_at: null, content: { tls: { scan: { quic: { enabled: true, ports: [443] } } }, ipsec: { ike: { versions: ["IKEv1"] } } } }] }];
  if (path === "/policies") return [{ id: "tls-policy", name: "TLS", description: "", technology: "tls", archived: false, versions: [{ id: "pt", version: 1, status: "published", published_at: null, content: {} }] }];
  if (path.includes("technology=ipsec")) return [{ id: "ike-policy", name: "IKE", description: "", technology: "ipsec", archived: false, versions: [{ id: "pi", version: 1, status: "published", published_at: null, content: {} }] }];
  if (path.includes("technology=ssh")) return [];
  return [];
});

vi.mock("../auth/AuthContext", () => ({ useAuth: () => ({ user: { id: "u1", role: "ADMIN" }, atLeast: () => true }) }));
vi.mock("../api/client", async (original) => ({ ...(await original<typeof import("../api/client")>()), api }));

afterEach(() => { cleanup(); api.mockClear(); });

describe("QUIC per-scan setting", () => {
  it("inherits the published TLS profile, allows a scan-only override, and restores inheritance", async () => {
    render(<I18nProvider initial="en"><MemoryRouter initialEntries={["/scans"]}><Scans /></MemoryRouter></I18nProvider>);
    fireEvent.click(await screen.findByRole("button", { name: "New scan" }));
    const profile = await screen.findByLabelText("Scan profile");
    await screen.findByRole("option", { name: "QUIC profile" });
    fireEvent.change(profile, { target: { value: "profile-1" } });
    const quic = await screen.findByRole("checkbox", { name: /Run QUIC \/ HTTP\/3 discovery for this scan/ });
    await waitFor(() => expect(quic).toBeChecked());
    fireEvent.click(quic);
    await waitFor(() => expect(quic).not.toBeChecked());
    fireEvent.click(screen.getByRole("button", { name: "Use the profile setting" }));
    await waitFor(() => expect(quic).toBeChecked());
    expect(screen.getByText(/inherits that setting/)).toBeInTheDocument();
  });
});
