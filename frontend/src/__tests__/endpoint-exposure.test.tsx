// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "../test-utils";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { I18nProvider } from "../i18n";
import { EndpointExposureEditor } from "../components/EndpointExposureEditor";

const apiMock = vi.hoisted(() => vi.fn());
vi.mock("../api/client", () => ({ api: apiMock }));
vi.mock("../auth/AuthContext", () => ({ useAuth: () => ({ user: { id: "operator", role: "OPERATOR" }, atLeast: (role: string) => role === "OPERATOR" }) }));

describe("endpoint exposure evidence", () => {
  beforeEach(() => {
    apiMock.mockReset();
    apiMock.mockImplementation(async (path: string, options?: { method?: string; body?: unknown }) => {
      if (path === "/targets/target-1/exposures" && !options?.method) return [];
      if (path === "/targets/target-1/exposures" && options?.method === "POST") return { id: "exposure-1" };
      return [];
    });
  });
  afterEach(cleanup);

  it("records explicit endpoint provenance and never validates as an operator", async () => {
    render(<I18nProvider initial="en"><EndpointExposureEditor targetId="target-1" /></I18nProvider>);
    await screen.findByText("Endpoint exposure context");
    expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Internet exposure"), { target: { value: "internet_confirmed" } });
    fireEvent.change(screen.getByLabelText("Evidence method"), { target: { value: "admin_attested" } });
    fireEvent.change(screen.getByLabelText("Source / reference"), { target: { value: "Firewall review #42" } });
    fireEvent.change(screen.getByLabelText("Justification"), { target: { value: "Reviewed by network operations" } });
    fireEvent.click(screen.getByRole("button", { name: "Add context" }));
    await waitFor(() => expect(apiMock).toHaveBeenCalledWith("/targets/target-1/exposures", expect.objectContaining({
      method: "POST",
      body: expect.objectContaining({ protocol: "tls", port: 443, state: "internet_confirmed", validated: false,
        source: "Firewall review #42", justification: "Reviewed by network operations" }),
    })));
  });
});
