// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, within } from "../test-utils";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import Shell from "../components/Shell";
import { I18nProvider } from "../i18n";

const auth = vi.hoisted(() => ({ role: "ADMIN" }));
const ranks: Record<string, number> = { AUDITOR: 1, USER: 2, OPERATOR: 3, ADMIN: 4 };
vi.mock("../auth/AuthContext", () => ({
  useAuth: () => ({
    user: { role: auth.role },
    atLeast: (role: string) => ranks[auth.role] >= ranks[role],
    logout: vi.fn(),
  }),
}));

afterEach(cleanup);
beforeEach(() => { auth.role = "ADMIN"; window.localStorage.clear(); });

function openShell(path = "/scans/map") {
  return render(<I18nProvider initial="en"><MemoryRouter initialEntries={[path]}><Routes>
    <Route element={<Shell />}><Route path="*" element={<div>Page content</div>} /></Route>
  </Routes></MemoryRouter></I18nProvider>);
}

describe("application shell navigation", () => {
  it("opens the group for a direct route and allows navigation groups to collapse", () => {
    openShell();
    const navigation = screen.getByRole("navigation", { name: "Main" });
    const scanning = within(navigation).getByRole("button", { name: "Scanning" });
    expect(scanning).toHaveAttribute("aria-expanded", "true");
    expect(within(navigation).getByRole("link", { name: "Exposure map" })).toHaveClass("active");
    expect(within(navigation).getByRole("link", { name: "Scans" })).not.toHaveAttribute("aria-current", "page");
    fireEvent.click(scanning);
    expect(scanning).toHaveAttribute("aria-expanded", "false");
    expect(within(navigation).queryByRole("link", { name: "Exposure map" })).toBeNull();
    const workspace = within(navigation).getByRole("button", { name: "Workspace" });
    fireEvent.click(workspace);
    expect(workspace).toHaveAttribute("aria-expanded", "true");
    expect(within(navigation).getByRole("link", { name: "Dashboard" })).toBeInTheDocument();
  });

  it("persists compact mode and keeps icon navigation labelled", () => {
    const first = openShell();
    fireEvent.click(screen.getByRole("button", { name: "Collapse sidebar" }));
    expect(document.querySelector(".sidebar")).toHaveClass("sidebar--compact");
    expect(window.localStorage.getItem("orion.sidebar-compact")).toBe("true");
    expect(screen.getByRole("link", { name: "Exposure map" })).toHaveAttribute("title", "Exposure map");
    first.unmount();
    openShell();
    expect(document.querySelector(".sidebar")).toHaveClass("sidebar--compact");
    fireEvent.click(screen.getByRole("button", { name: "Expand sidebar" }));
    expect(document.querySelector(".sidebar")).not.toHaveClass("sidebar--compact");
    expect(window.localStorage.getItem("orion.sidebar-compact")).toBe("false");
  });

  it("shows the Orion name and adopts the compact choice saved before the rebranding", () => {
    window.localStorage.setItem("tls-scan.sidebar-compact", "true");
    openShell();
    expect(document.querySelector(".brand-title")).toHaveTextContent("Orion");
    expect(document.querySelector(".sidebar")).toHaveClass("sidebar--compact");
    expect(window.localStorage.getItem("orion.sidebar-compact")).toBe("true");
    expect(window.localStorage.getItem("tls-scan.sidebar-compact")).toBeNull();
  });

  it("keeps the existing mobile menu and closes it with Escape", () => {
    openShell();
    const menu = document.querySelector<HTMLButtonElement>(".mobile-menu")!;
    fireEvent.click(menu);
    expect(document.querySelector(".sidebar")).toHaveClass("sidebar--open");
    fireEvent.keyDown(window, { key: "Escape" });
    expect(document.querySelector(".sidebar")).not.toHaveClass("sidebar--open");
    expect(menu).toHaveFocus();
  });

  it("keeps report access under Scans for auditors without a separate Reports entry", () => {
    auth.role = "AUDITOR";
    openShell("/");
    const navigation = screen.getByRole("navigation", { name: "Main" });
    expect(within(navigation).getByRole("link", { name: "Dashboard" })).toBeInTheDocument();
    fireEvent.click(within(navigation).getByRole("button", { name: "Scanning" }));
    expect(within(navigation).getByRole("link", { name: "Scans" })).toBeInTheDocument();
    expect(within(navigation).queryByRole("link", { name: "Reports" })).toBeNull();
    expect(within(navigation).queryByRole("button", { name: "Administration" })).toBeNull();
  });
});
