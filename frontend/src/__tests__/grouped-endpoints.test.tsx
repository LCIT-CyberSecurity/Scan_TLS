// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import type { Endpoint } from "../api/types";
import { GroupedEndpoints } from "../components/GroupedEndpoints";
import type { Column } from "../components/DataTable";
import { I18nProvider } from "../i18n";

afterEach(cleanup);
const ep = (host: string, port: string, grade: string, status: string, extra: Partial<Endpoint> = {}): Endpoint => ({
  endpoint_id: `${host}:${port}`, hostname: host, ip_address: "10.0.0.1", port, grade, compliance_status: status, highest_severity: "", tls_versions: ["TLS 1.2"],
  certificate: { valid_until: "2027-01-01" }, errors: [], untested_checks: [], ...extra,
});
const columns: Column<Endpoint>[] = ["endpoint", "tags", "grade", "status", "tls", "cert"].map((key) => ({ key, header: key, render: (e: Endpoint) => (key === "endpoint" ? `${e.hostname}:${e.port}` : key === "grade" ? e.grade : "") }));
const rows = [ep("web", "443", "A", "compliant"), ep("web", "8443", "F", "non_compliant", { tls_versions: ["TLS 1.0"] }), ep("db", "5432", "B", "compliant")];

describe("GroupedEndpoints", () => {
  it("groups the ports of a host behind a chevron and shows the worst grade", () => {
    render(<I18nProvider initial="en"><GroupedEndpoints rows={rows} columns={columns} /></I18nProvider>);
    expect(screen.getByText("web")).toBeInTheDocument();
    expect(screen.getByText("2 endpoints")).toBeInTheDocument();
    expect(screen.getByText("1/2 non_compliant")).toBeInTheDocument();
    expect(screen.getByText("TLS 1.0, TLS 1.2")).toBeInTheDocument();
    expect(screen.queryByText("web:443")).not.toBeInTheDocument();  // folded
    expect(screen.getByText("db:5432")).toBeInTheDocument();  // a host with one endpoint is a plain row
    const toggle = screen.getByRole("button", { name: "Show the endpoints of this host" });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    fireEvent.click(toggle);
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByText("web:443")).toBeInTheDocument();
    expect(screen.getByText("web:8443")).toBeInTheDocument();
  });
});
