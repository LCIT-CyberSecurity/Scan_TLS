// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { I18nProvider } from "../i18n";
import Login from "../pages/Login";

const calls: { path: string; method: string; body?: unknown }[] = [];
let providers: Record<string, unknown> = {};
const refresh = vi.fn();
vi.mock("../auth/AuthContext", () => ({ useAuth: () => ({ user: null, login: vi.fn(), refresh }) }));
vi.mock("../api/client", async (original) => ({
  ...(await original<typeof import("../api/client")>()),
  api: vi.fn(async (path: string, options: { method?: string; body?: unknown } = {}) => {
    calls.push({ path, method: options.method ?? "GET", body: options.body });
    if (path === "/auth/providers") return providers;
    if (path === "/auth/ldap/login") return { user: {}, csrf_token: "x" };
    throw new Error(`unexpected ${path}`);
  }),
}));

afterEach(cleanup);
beforeEach(() => { calls.length = 0; refresh.mockClear(); });
const open = async () => { render(<I18nProvider><Login /></I18nProvider>); await waitFor(() => expect(calls.some((c) => c.path === "/auth/providers")).toBe(true)); };
const NO = { local: true, sso: { enabled: false }, ldap: { enabled: false } };

describe("login page", () => {
  it("without an external provider it is exactly the local sign-in", async () => {
    providers = NO;
    await open();
    expect(await screen.findByLabelText("Username or e-mail")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Sign in with/ })).toBeNull();
    expect(screen.queryByRole("button", { name: "Local sign-in" })).toBeNull();      // no disabled button for a provider that is not configured
  });

  it("Entra ID: the Microsoft button first, the local form behind a discreet link", async () => {
    providers = { ...NO, sso: { enabled: true, provider: "entra" } };
    await open();
    expect(await screen.findByRole("button", { name: "Sign in with Microsoft" })).toBeInTheDocument();
    expect(screen.queryByLabelText("Username or e-mail")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Local sign-in" }));
    expect(await screen.findByLabelText("Username or e-mail")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Sign in with Microsoft" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Back to the main sign-in" }));
    expect(await screen.findByRole("button", { name: "Sign in with Microsoft" })).toBeInTheDocument();
  });

  it("Google Workspace has its own button", async () => {
    providers = { ...NO, sso: { enabled: true, provider: "google" } };
    await open();
    expect(await screen.findByRole("button", { name: "Sign in with Google" })).toBeInTheDocument();
  });

  it("a generic OIDC provider keeps the historical label", async () => {
    providers = { ...NO, sso: { enabled: true, provider: "generic" } };
    await open();
    expect(await screen.findByRole("button", { name: "Sign in with SSO" })).toBeInTheDocument();
  });

  it("LDAP: the directory form posts to the LDAP endpoint, the local sign-in stays reachable", async () => {
    providers = { ...NO, ldap: { enabled: true, name: "corp" } };
    await open();
    fireEvent.change(await screen.findByLabelText("Username or e-mail"), { target: { value: "alice" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "Secret-Pass-1" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    await waitFor(() => expect(calls.at(-1)).toMatchObject({ path: "/auth/ldap/login", method: "POST", body: { username: "alice", password: "Secret-Pass-1" } }));
    await waitFor(() => expect(refresh).toHaveBeenCalled());
    fireEvent.click(screen.getByRole("button", { name: "Local sign-in" }));
    expect(await screen.findByLabelText("Username or e-mail")).toBeInTheDocument();
  });
});
