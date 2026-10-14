// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DirectoryUserImport } from "../components/DirectoryUserImport";
import { I18nProvider } from "../i18n";

const calls: { path: string; method: string; body?: unknown }[] = [];
let imported = false;

vi.mock("../api/client", async (original) => ({
  ...(await original<typeof import("../api/client")>()),
  api: vi.fn(async (path: string, options: { method?: string; body?: unknown } = {}) => {
    calls.push({ path, method: options.method ?? "GET", body: options.body });
    if (path === "/admin/directory") return { kind: "ldap" };
    if (path === "/admin/directory/search") return [{ external_id: "ldap-123", email: "alice@example.org", display_name: "Alice Example", provisioned: imported }];
    if (path === "/admin/directory/provision") { imported = true; return {}; }
    throw new Error(`unexpected ${path}`);
  }),
}));

afterEach(cleanup);
beforeEach(() => { calls.length = 0; imported = false; });

describe("directory account import in Administration → Users", () => {
  it("lets an administrator select an account and assign its TLS Scan role before import", async () => {
    render(<I18nProvider><DirectoryUserImport /></I18nProvider>);
    const search = await screen.findByLabelText("Search a person (name or e-mail)");
    fireEvent.change(search, { target: { value: "alice" } });
    fireEvent.click(screen.getByRole("button", { name: "Search" }));
    expect(await screen.findByText("Alice Example")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Role alice@example.org"), { target: { value: "OPERATOR" } });
    fireEvent.click(screen.getByRole("button", { name: "Add with role" }));

    await waitFor(() => expect(calls.find((call) => call.path === "/admin/directory/provision")?.body).toEqual({
      email: "alice@example.org", display_name: "Alice Example", role: "OPERATOR",
    }));
    expect(await screen.findByText("Already has an account")).toBeInTheDocument();
  });
});
