// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { I18nProvider } from "../i18n";
import Login from "../pages/Login";

const calls: { path: string; method: string; body?: unknown }[] = [];
let providers: Record<string, unknown> = {};
let providerError = false;
let currentUser: { must_change_password?: boolean } | null = null;
const refresh = vi.fn();
const login = vi.fn();
vi.mock("../auth/AuthContext", () => ({ useAuth: () => ({ user: currentUser, login, refresh }) }));
vi.mock("../api/client", async (original) => ({
  ...(await original<typeof import("../api/client")>()),
  api: vi.fn(async (path: string, options: { method?: string; body?: unknown } = {}) => {
    calls.push({ path, method: options.method ?? "GET", body: options.body });
    if (path === "/auth/providers") {
      if (providerError) throw new Error("provider endpoint unavailable");
      return providers;
    }
    if (path === "/auth/ldap/login") return { user: {}, csrf_token: "x" };
    if (path === "/auth/password") return {};
    throw new Error(`unexpected ${path}`);
  }),
}));

afterEach(() => { cleanup(); window.history.replaceState({}, "", "/login"); });
beforeEach(() => {
  calls.length = 0; refresh.mockClear(); login.mockReset(); providerError = false; currentUser = null;
});
const open = async () => {
  render(<I18nProvider><Login /></I18nProvider>);
  await waitFor(() => expect(calls.some((c) => c.path === "/auth/providers")).toBe(true));
};
const localOnly = { local: true, sso: { enabled: false }, ldap: { enabled: false } };

async function chooseDetails(label = "Other sign-in methods") {
  const details = await screen.findByText(label).then((summary) => summary.closest("details"));
  expect(details).not.toBeNull();
  expect(details).not.toHaveAttribute("open");
  fireEvent.click(details!.querySelector("summary")!);
  return details!;
}

describe("login page", () => {
  it("uses one provider-agnostic SSO action and keeps local access collapsed", async () => {
    providers = { ...localOnly, sso: { enabled: true, provider: "entra" } };
    await open();
    expect(await screen.findByRole("link", { name: "Sign in" })).toHaveAttribute("href", "/api/auth/sso/login");
    expect(screen.queryByRole("button", { name: /Microsoft|Google|SSO/i })).toBeNull();
    const details = await screen.findByText("Other sign-in methods").then((summary) => summary.closest("details"));
    expect(details).not.toHaveAttribute("open");
    await chooseDetails();
    expect(screen.getAllByLabelText("Username or e-mail")[0]).toBeVisible();
    expect(screen.getByRole("button", { name: "Sign in" })).toBeInTheDocument();
  });

  it("shows LDAP and local choices with only one form when both alternatives are enabled", async () => {
    providers = { local: true, sso: { enabled: true, provider: "google" }, ldap: { enabled: true, name: "corp" } };
    await open();
    await chooseDetails();
    expect(screen.getByRole("radio", { name: "Directory account" })).toBeChecked();
    expect(screen.getAllByLabelText("Username or e-mail")).toHaveLength(1);
    fireEvent.click(screen.getByRole("radio", { name: "Local account" }));
    fireEvent.change(screen.getByLabelText("Username or e-mail"), { target: { value: "alice" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "Secret-Pass-1" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    await waitFor(() => expect(login).toHaveBeenCalledWith("alice", "Secret-Pass-1"));
    expect(calls.some((call) => call.path === "/auth/ldap/login")).toBe(false);
  });

  it("uses the LDAP endpoint when the directory alternative is selected", async () => {
    providers = { local: true, sso: { enabled: true }, ldap: { enabled: true, name: "corp" } };
    await open();
    await chooseDetails();
    fireEvent.change(await screen.findByLabelText("Username or e-mail"), { target: { value: "alice" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "Secret-Pass-1" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    await waitFor(() => expect(calls.at(-1)).toMatchObject({ path: "/auth/ldap/login", method: "POST", body: { username: "alice", password: "Secret-Pass-1" } }));
    expect(refresh).toHaveBeenCalled();
  });

  it("shows LDAP immediately without SSO and keeps local recovery discreet", async () => {
    providers = { local: true, sso: { enabled: false }, ldap: { enabled: true } };
    await open();
    await waitFor(() => expect(screen.getAllByLabelText("Username or e-mail")[0]).toBeVisible());
    expect(screen.queryByRole("link", { name: "Sign in" })).toBeNull();
    const details = screen.getByText("Local account").closest("details");
    expect(details).not.toHaveAttribute("open");
  });

  it("shows local credentials immediately when SSO and LDAP are unavailable", async () => {
    providers = localOnly;
    await open();
    expect(await screen.findByLabelText("Username or e-mail")).toBeInTheDocument();
    expect(screen.queryByText("Other sign-in methods")).toBeNull();
    expect(screen.queryByRole("link", { name: "Sign in" })).toBeNull();
  });

  it("preserves the local recovery path and reports provider discovery failure", async () => {
    providerError = true;
    await open();
    expect(await screen.findByLabelText("Username or e-mail")).toBeInTheDocument();
    expect(screen.getByText("Sign-in options could not be loaded. Local sign-in is available.")).toBeInTheDocument();
  });

  it("shows a safe SSO callback error and keeps the alternate login available", async () => {
    window.history.replaceState({}, "", "/login?auth_error=sso_unavailable&secret=hidden");
    providers = { ...localOnly, sso: { enabled: true, provider: "generic" } };
    await open();
    expect(await screen.findByText("Single sign-on failed. Try again or use another sign-in method.")).toBeInTheDocument();
    expect(window.location.search).toBe("");
    expect(screen.queryByText("hidden")).toBeNull();
  });

  it("keeps the forced password-change form and endpoint", async () => {
    currentUser = { must_change_password: true };
    providers = localOnly;
    await open();
    fireEvent.change(await screen.findByLabelText("Current password"), { target: { value: "Old-Pass-1" } });
    fireEvent.change(screen.getByLabelText("New password"), { target: { value: "New-Pass-Strong-1" } });
    fireEvent.click(screen.getByRole("button", { name: "Change password and continue" }));
    await waitFor(() => expect(calls.at(-1)).toMatchObject({ path: "/auth/password", method: "POST", body: { current_password: "Old-Pass-1", new_password: "New-Pass-Strong-1" } }));
  });

  it("translates the primary and alternatives into French", async () => {
    providers = { ...localOnly, sso: { enabled: true } };
    render(<I18nProvider initial="fr"><Login /></I18nProvider>);
    await waitFor(() => expect(calls.some((c) => c.path === "/auth/providers")).toBe(true));
    expect(await screen.findByRole("link", { name: "Se connecter" })).toHaveAttribute("href", "/api/auth/sso/login");
    expect(screen.getByText("Autres méthodes de connexion")).toBeInTheDocument();
  });
});
