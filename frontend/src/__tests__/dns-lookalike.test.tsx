// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "../test-utils";
import { DnsLookalikeMonitors } from "../components/DnsLookalikeMonitors";
import { I18nProvider } from "../i18n";

const calls: { path: string; method: string; body?: unknown }[] = [];
let monitors: unknown[] = [];
vi.mock("../api/client", async (original) => ({
  ...(await original<typeof import("../api/client")>()),
  api: vi.fn(async (path: string, options: { method?: string; body?: unknown } = {}) => {
    const method = options.method ?? "GET";
    calls.push({ path, method, body: options.body });
    if (method === "GET" && path === "/dns-lookalike-monitors") return monitors;
    if (method === "POST" && path === "/dns-lookalike-monitors") return {};
    throw new Error(`unexpected request ${method} ${path}`);
  }),
}));
vi.mock("../auth/AuthContext", () => ({ useAuth: () => ({ user: { role: "ADMIN" } }) }));

afterEach(cleanup);
beforeEach(() => { calls.length = 0; monitors = []; });
const wrap = () => render(<I18nProvider><DnsLookalikeMonitors /></I18nProvider>);

describe("DNS lookalike monitoring", () => {
  it("stays paused and makes no discovery request until an administrator explicitly enables a domain", async () => {
    wrap();
    const domain = await screen.findByLabelText("Reference domain");
    expect(calls.filter((call) => call.method === "POST")).toHaveLength(0);
    fireEvent.change(domain, { target: { value: "example.com" } });
    const create = screen.getByRole("button", { name: "Create monitoring" });
    expect(create).toBeDisabled();
    fireEvent.click(screen.getByLabelText(/I confirm I am authorised/));
    expect(create).toBeEnabled();
    fireEvent.click(create);
    await waitFor(() => expect(calls.some((call) => call.method === "POST")).toBe(true));
    expect(calls.find((call) => call.method === "POST")?.body).toMatchObject({ domain: "example.com", authorized: true, enabled: false, ct_enabled: false, notifications_enabled: false });
  });
});
