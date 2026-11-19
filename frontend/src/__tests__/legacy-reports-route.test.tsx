// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "../test-utils";
import { afterEach, describe, expect, it } from "vitest";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { I18nProvider } from "../i18n";
import { LegacyReportsRedirect } from "../App";

function Location() {
  const location = useLocation();
  return <output>{location.pathname}{location.search}</output>;
}

afterEach(cleanup);

describe("legacy Reports routes", () => {
  it("redirects the reports list and keeps its filters in the Scans reports tab", async () => {
    render(<I18nProvider initial="en"><MemoryRouter initialEntries={["/reports?tag=prod&si=si-1"]}><Routes>
      <Route path="/reports" element={<LegacyReportsRedirect />} />
      <Route path="/scans" element={<Location />} />
    </Routes></MemoryRouter></I18nProvider>);
    expect(await screen.findByText("/scans?tag=prod&si=si-1&tab=reports")).toBeInTheDocument();
  });

  it("redirects a legacy run and report-format link to the corresponding filtered report", async () => {
    render(<I18nProvider initial="en"><MemoryRouter initialEntries={["/reports/run-1/html"]}><Routes>
      <Route path="/reports/:runId/:format" element={<LegacyReportsRedirect />} />
      <Route path="/scans" element={<Location />} />
    </Routes></MemoryRouter></I18nProvider>);
    expect(await screen.findByText("/scans?tab=reports&run_id=run-1&format=html")).toBeInTheDocument();
  });
});
