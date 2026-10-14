// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuthSettings } from "../components/AuthSettings";
import { I18nProvider } from "../i18n";

const calls: { path: string; method: string; body?: any }[] = []; // eslint-disable-line @typescript-eslint/no-explicit-any
const STORED = { provider: "", entra: { tenant_id: "", client_id: "", issuer: "" }, google: { client_id: "", allowed_domains: [] }, ldap: { name: "", server_url: "", base_dn: "", login_attribute: "uid", user_filter: "(objectClass=person)", bind_dn: "", starttls: false, ca_pem: "", email_attribute: "mail", name_attribute: "cn", id_attribute: "entryUUID" }, default_role: null, auto_provision: null };
let DATA = { stored: STORED, redirect_uri: "https://scan.example.org/api/auth/sso/callback", effective: { provider: "", source: "none", issuer: "", client_id: "", default_role: "USER", auto_provision: false, complete: false },
  secrets: { oidc_client_secret: true, google_client_secret: false, ldap_bind_password: false }, environment: { oidc_configured: false, oidc_provider: "", auto_provision: null } };
vi.mock("../api/client", async (original) => ({
  ...(await original<typeof import("../api/client")>()),
  api: vi.fn(async (path: string, options: { method?: string; body?: any } = {}) => { // eslint-disable-line @typescript-eslint/no-explicit-any
    calls.push({ path, method: options.method ?? "GET", body: options.body });
    if (path === "/admin/auth" && !options.method) return DATA;
    if (path === "/admin/auth" && options.method === "PUT") { DATA.stored = options.body.value; return DATA; }   // the server keeps what was saved
    if (path === "/admin/auth/diagnostics") return [{ at: "2026-10-13T10:00:00Z", action: "auth.sso_login", who: "entra", outcome: "failure", ip: "10.0.0.1", reason: "oidc_exchange_failed", code: "aadsts50011", explanation: "The redirect URI sent by TLS Scan is not registered." }];
    if (path.startsWith("/admin/auth/test/")) return [{ step: "configuration", status: "ok", detail: "" }, { step: "issuer reachable", status: "fail", detail: "cannot reach" }, { step: "interactive sign-in", status: "info", detail: "A real sign-in is required." }];
    throw new Error(`unexpected ${path}`);
  }),
}));

afterEach(cleanup);
beforeEach(() => { calls.length = 0; DATA = { ...DATA, stored: STORED }; });

describe("Administration → Authentication", () => {
  it("shows the active mode, the redirect URI and the state of the secrets, never a secret", async () => {
    render(<I18nProvider><AuthSettings /></I18nProvider>);
    await screen.findByText("Active sign-in", { exact: false });
    expect(screen.getByText("Local accounts only", { selector: "span" })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Sign-in provider"), { target: { value: "entra" } });
    expect(await screen.findByText("https://scan.example.org/api/auth/sso/callback")).toBeInTheDocument();
    expect(screen.getByText("secret set")).toBeInTheDocument();
    expect(screen.getByText(/TLS_SCAN_OIDC_CLIENT_SECRET/)).toBeInTheDocument();
    expect(screen.queryByLabelText(/client secret/i)).toBeNull();                            // no field to type a secret in
  });

  it("saves the non-secret Entra settings and runs the step-by-step test with its honest last step", async () => {
    render(<I18nProvider><AuthSettings /></I18nProvider>);
    fireEvent.change(await screen.findByLabelText("Sign-in provider"), { target: { value: "entra" } });
    fireEvent.change(screen.getByLabelText("Tenant ID"), { target: { value: "11111111-2222-3333-4444-555555555555" } });
    fireEvent.change(screen.getByLabelText("Client ID"), { target: { value: "app-id" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PUT")?.body.value).toMatchObject({ provider: "entra", entra: { tenant_id: "11111111-2222-3333-4444-555555555555", client_id: "app-id" } }));
    fireEvent.click(await screen.findByRole("button", { name: "Test the configuration" }));
    const list = await screen.findByRole("list", { name: "Test the configuration" });
    expect(within(list).getByText("issuer reachable")).toBeInTheDocument();
    expect(within(list).getByText("Failed")).toBeInTheDocument();
    expect(within(list).getByText("A real sign-in is required.")).toBeInTheDocument();
  });

  it("Google: allowed Workspace domains, one per line", async () => {
    render(<I18nProvider><AuthSettings /></I18nProvider>);
    fireEvent.change(await screen.findByLabelText("Sign-in provider"), { target: { value: "google" } });
    fireEvent.change(screen.getByLabelText("Allowed Workspace domains"), { target: { value: "corp.example\nsub.corp.example" } });
    expect(screen.getByText("secret missing")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PUT")?.body.value.google.allowed_domains).toEqual(["corp.example", "sub.corp.example"]));
  });

  it("LDAP: the user test only runs on an explicit click and clears the password afterwards", async () => {
    render(<I18nProvider><AuthSettings /></I18nProvider>);
    fireEvent.change(await screen.findByLabelText("Sign-in provider"), { target: { value: "ldap" } });
    const run = screen.getByRole("button", { name: "Test this sign-in" });
    expect(run).toBeDisabled();
    const box = screen.getByText("Test a user sign-in (optional)").closest("fieldset") as HTMLElement;
    fireEvent.change(within(box).getByLabelText("Username or e-mail"), { target: { value: "alice" } });
    fireEvent.change(within(box).getByLabelText("Password"), { target: { value: "pw-once" } });
    fireEvent.click(run);
    await waitFor(() => expect(calls.find((c) => c.path === "/admin/auth/test/ldap")?.body).toEqual({ username: "alice", password: "pw-once" }));
    await waitFor(() => expect((within(box).getByLabelText("Password") as HTMLInputElement).value).toBe(""));
  });

  it("lists the latest failures with their explanation", async () => {
    render(<I18nProvider><AuthSettings /></I18nProvider>);
    expect(await screen.findByText("aadsts50011")).toBeInTheDocument();
    expect(screen.getByText(/redirect URI sent by TLS Scan is not registered/)).toBeInTheDocument();
  });
});
