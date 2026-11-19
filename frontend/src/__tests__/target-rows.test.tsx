// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "../test-utils";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "../api/client";
import { I18nProvider } from "../i18n";
import { TargetDialog } from "../pages/Targets";

vi.mock("../api/client", async (original) => ({
  ...(await original<typeof import("../api/client")>()),
  api: vi.fn(),
}));
afterEach(() => { cleanup(); vi.resetAllMocks(); });

it("keeps the successful row and sends only the corrected row on retry", async () => {
  const onSaved = vi.fn();
  vi.mocked(api).mockResolvedValueOnce([
    { status: "created", target: { id: "one" } }, { status: "invalid" },
  ]).mockResolvedValueOnce([{ status: "created", target: { id: "two" } }]);
  render(<I18nProvider><TargetDialog enableRows systems={[]} onSaved={onSaved} onClose={vi.fn()} /></I18nProvider>);
  const add = screen.getByRole("button", { name: "Add a row" });
  expect(screen.queryByRole("button", { name: /Remove row/ })).toBeNull();
  fireEvent.click(add);
  const rows = screen.getAllByPlaceholderText(/www.example.org/);
  fireEvent.change(rows[0], { target: { value: "2001:db8::1" } });
  fireEvent.change(rows[1], { target: { value: "bad/99" } });
  const save = screen.getByRole("button", { name: "Save" });
  fireEvent.click(save);
  expect(await screen.findByText("Invalid value")).toBeInTheDocument();
  expect(rows[0]).toBeDisabled();
  expect(onSaved).toHaveBeenCalledWith({ id: "one" });
  fireEvent.change(rows[1], { target: { value: "192.0.2.0/24" } });
  fireEvent.click(save);
  await waitFor(() => expect(screen.getAllByText("Created")).toHaveLength(2));
  expect(api).toHaveBeenLastCalledWith("/targets/rows", {
    method: "POST", body: expect.objectContaining({ values: ["192.0.2.0/24"] }),
  });
});
