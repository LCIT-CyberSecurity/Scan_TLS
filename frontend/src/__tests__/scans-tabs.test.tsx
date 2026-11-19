// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "../test-utils";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter, useLocation } from "react-router-dom";
import Scans from "../pages/Scans";
import { I18nProvider } from "../i18n";

vi.mock("../auth/AuthContext", () => ({ useAuth: () => ({ user: { id: "u1", role: "ADMIN" }, atLeast: () => true }) }));
vi.mock("../api/client", async (original) => ({
  ...(await original<typeof import("../api/client")>()),
  api: vi.fn(async () => []),
}));

function CurrentUrl() {
  const { pathname, search } = useLocation();
  return <output aria-label="current route">{pathname}{search}</output>;
}

afterEach(cleanup);

describe("Scans route tabs", () => {
  it("offers Scans, History and Reports as shareable tabs and updates the URL", async () => {
    render(<I18nProvider initial="en"><MemoryRouter initialEntries={["/scans"]}><>
      <Scans />
      <CurrentUrl />
    </></MemoryRouter></I18nProvider>);

    expect(await screen.findByRole("tab", { name: "Scans" })).toHaveAttribute("aria-selected", "false");
    expect(screen.getByRole("tab", { name: "History" })).toHaveAttribute("aria-selected", "true");
    fireEvent.mouseDown(screen.getByRole("tab", { name: "Scans" }));
    await waitFor(() => expect(screen.getByLabelText("current route")).toHaveTextContent("/scans?tab=scans"));
    fireEvent.mouseDown(screen.getByRole("tab", { name: "Reports" }));
    await waitFor(() => expect(screen.getByLabelText("current route")).toHaveTextContent("/scans?tab=reports"));
    expect(screen.getByLabelText("From")).toBeInTheDocument();
    expect(screen.getByLabelText("To")).toBeInTheDocument();
  });
});
