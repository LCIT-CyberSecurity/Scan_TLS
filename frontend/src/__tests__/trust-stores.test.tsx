// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Endpoint, TrustStoreDetail, TrustStoreSummary } from "../api/types";
import { PkiTrust } from "../components/PkiTrust";
import { TrustStoresTab } from "../components/TrustStores";
import { I18nProvider } from "../i18n";
import { TrustAuthorities } from "../pages/Policies";

const calls: { path: string; method: string; body?: unknown }[] = [];
let responses: Record<string, unknown> = {};
vi.mock("../api/client", async (original) => ({
  ...(await original<typeof import("../api/client")>()),
  api: vi.fn(async (path: string, options: { method?: string; body?: unknown } = {}) => {
    calls.push({ path, method: options.method ?? "GET", body: options.body });
    const key = `${options.method ?? "GET"} ${path}`;
    if (!(key in responses)) throw new Error(`unexpected call ${key}`);
    const value = responses[key];
    if (value instanceof Error) throw value;
    return value;
  }),
}));

afterEach(cleanup);
beforeEach(() => { calls.length = 0; responses = {}; vi.spyOn(window, "confirm").mockReturnValue(true); });
const wrap = (ui: React.ReactNode) => render(<I18nProvider>{ui}</I18nProvider>);

const builtin: TrustStoreSummary = { id: "public-web-pki", name: "TLS Scan Public Web PKI", description: "Mozilla", builtin: true, type: "public", active: true, version: null, certificate_count: 146, anchor_count: null, has_expired: false, updated_at: null };
const acme: TrustStoreSummary = { id: "11111111-1111-4111-8111-111111111111", name: "Client A - PKI interne", description: "PKI A", builtin: false, type: "private", active: true, version: 2, certificate_count: 2, anchor_count: 1, has_expired: false, updated_at: "2026-10-12T10:00:00Z" };
const cert = (role: "anchor" | "intermediate", cn: string, extra = {}) => ({ fingerprint_sha256: `${cn}`.padEnd(64, "a"), role, subject: `CN=${cn}`, issuer: "CN=ACME-Root-CA", serial: "01", not_before: "2026-01-01T00:00:00Z", not_after: "2036-01-01T00:00:00Z", key_type: "RSA", key_size: 2048, signature_algorithm: "sha256", basic_constraints: { ca: true, path_length: null }, key_usage: ["key_cert_sign"], expired: false, expires_in_days: 3000, ...extra });
const detail: TrustStoreDetail = { ...acme, content_sha256: "ab".repeat(32), certificates: [cert("anchor", "ACME-Root-CA"), cert("intermediate", "ACME-Issuing-CA")], versions: [{ id: "v2", version: 2, content_sha256: "ab".repeat(32), comment: "add issuing", created_at: "2026-10-12T10:00:00Z", anchor_count: 1, intermediate_count: 1 }, { id: "v1", version: 1, content_sha256: "cd".repeat(32), comment: "", created_at: "2026-10-11T10:00:00Z", anchor_count: 1, intermediate_count: 0 }], profiles: [{ id: "p1", name: "Infrastructure interne", versions: [1] }], run_count: 3 };

describe("administration: trust authorities", () => {
  it("lists the built-in store as read-only and the private stores with their state", async () => {
    responses["GET /admin/trust-stores"] = [builtin, { ...acme, active: false, has_expired: true }];
    wrap(<TrustStoresTab />);
    const row = await screen.findByText("TLS Scan Public Web PKI");
    const builtinRow = row.closest("tr")!;
    expect(within(builtinRow).getByText("Built-in public")).toBeInTheDocument();
    expect(within(builtinRow).queryByRole("button")).toBeNull(); // nothing to edit or delete
    const privateRow = screen.getByText("Client A - PKI interne").closest("tr")!;
    expect(within(privateRow).getByText("Private")).toBeInTheDocument();
    expect(within(privateRow).getByText("Inactive")).toBeInTheDocument();
    expect(within(privateRow).getByText("Expired")).toBeInTheDocument();
    expect(within(privateRow).getByRole("button", { name: "Details" })).toBeInTheDocument();
  });

  it("shows the empty state when no private store exists", async () => {
    responses["GET /admin/trust-stores"] = [builtin];
    wrap(<TrustStoresTab />);
    expect(await screen.findByText(/No private trust store yet/)).toBeInTheDocument();
  });

  it("previews an import with roles and refuses what the server refuses", async () => {
    responses["GET /admin/trust-stores"] = [builtin];
    responses["POST /admin/trust-stores/inspect"] = { valid: false, files: [
      { filename: "bundle.pem", error: null, certificates: [{ ...cert("anchor", "ACME-Root-CA"), error: null, duplicate: false }, { ...cert("intermediate", "ACME-Issuing-CA"), error: null, duplicate: true }] },
      { filename: "key.pem", error: "key.pem: private keys are refused; import the public CA certificate only", certificates: [] },
    ] };
    wrap(<TrustStoresTab />);
    fireEvent.click(await screen.findByRole("button", { name: /New trust store/ }));
    const dialog = await screen.findByRole("dialog");
    const input = within(dialog).getByLabelText(/CA certificate files/) as HTMLInputElement;
    const file = new File(["-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"], "bundle.pem");
    Object.defineProperty(input, "files", { value: [file] });
    fireEvent.change(input);
    expect((await within(dialog).findAllByText(/CN=ACME-Root-CA/)).length).toBeGreaterThan(0);
    expect(within(dialog).getByText("Root CA (trust anchor)")).toBeInTheDocument();
    expect(within(dialog).getByText("Intermediate CA")).toBeInTheDocument();
    expect(within(dialog).getByText("duplicate")).toBeInTheDocument();
    expect(within(dialog).getAllByRole("alert").some((a) => /private keys are refused/.test(a.textContent ?? ""))).toBe(true);
    // the raw content is sent as base64, with the name for display only
    const sent = calls.find((c) => c.path.endsWith("/inspect"))!.body as { files: { filename: string; content_b64: string }[] };
    expect(sent.files[0].filename).toBe("bundle.pem");
    expect(atob(sent.files[0].content_b64)).toContain("BEGIN CERTIFICATE");
  });

  it("creates a store: name and files are required, then posts them", async () => {
    responses["GET /admin/trust-stores"] = [builtin];
    responses["POST /admin/trust-stores/inspect"] = { valid: true, files: [{ filename: "root.pem", error: null, certificates: [{ ...cert("anchor", "ACME-Root-CA"), error: null, duplicate: false }] }] };
    responses["POST /admin/trust-stores"] = detail;
    responses[`GET /admin/trust-stores/${detail.id}`] = detail;
    wrap(<TrustStoresTab />);
    fireEvent.click(await screen.findByRole("button", { name: /New trust store/ }));
    const dialog = await screen.findByRole("dialog");
    const create = within(dialog).getByRole("button", { name: /Create and import/ });
    expect(create).toBeDisabled();
    fireEvent.change(within(dialog).getByLabelText("Name"), { target: { value: "Client A - PKI interne" } });
    const input = within(dialog).getByLabelText(/CA certificate files/) as HTMLInputElement;
    Object.defineProperty(input, "files", { value: [new File(["-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"], "root.pem")] });
    fireEvent.change(input);
    await within(dialog).findAllByText(/CN=ACME-Root-CA/);
    await waitFor(() => expect(create).toBeEnabled());
    fireEvent.click(create);
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/admin/trust-stores")).toBe(true));
    const body = calls.find((c) => c.method === "POST" && c.path === "/admin/trust-stores")!.body as { name: string; files: unknown[] };
    expect(body.name).toBe("Client A - PKI interne");
    expect(body.files).toHaveLength(1);
  });

  it("shows the certificates, versions and profiles of a store, and confirms before deactivating", async () => {
    responses["GET /admin/trust-stores"] = [builtin, acme];
    responses[`GET /admin/trust-stores/${acme.id}`] = detail;
    responses[`PUT /admin/trust-stores/${acme.id}`] = { ...detail, active: false };
    wrap(<TrustStoresTab />);
    fireEvent.click(await screen.findByRole("button", { name: "Details" }));
    const dialog = await screen.findByRole("dialog");
    expect(await within(dialog).findByText("CN=ACME-Root-CA")).toBeInTheDocument();
    expect(within(dialog).getByText("Root CA (trust anchor)")).toBeInTheDocument();
    expect(within(dialog).getByText("Infrastructure interne")).toBeInTheDocument();
    expect(within(dialog).getByText(/3 scan\(s\) used this store/)).toBeInTheDocument();
    expect(within(dialog).queryByRole("button", { name: "Delete" })).toBeNull(); // a referenced store cannot be deleted, only deactivated
    fireEvent.click(within(dialog).getAllByRole("button", { name: "Details" })[0]);
    expect(await within(dialog).findByText("SHA-256 fingerprint")).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole("button", { name: "Disable" }));
    expect(window.confirm).toHaveBeenCalledWith(expect.stringMatching(/Deactivate this store/));
    await waitFor(() => expect(calls.some((c) => c.method === "PUT" && (c.body as { active: boolean }).active === false)).toBe(true));
  });

  it("shows an unreferenced store with a delete button", async () => {
    responses["GET /admin/trust-stores"] = [builtin, acme];
    responses[`GET /admin/trust-stores/${acme.id}`] = { ...detail, profiles: [], run_count: 0 };
    wrap(<TrustStoresTab />);
    fireEvent.click(await screen.findByRole("button", { name: "Details" }));
    const dialog = await screen.findByRole("dialog");
    expect(await within(dialog).findByRole("button", { name: "Delete" })).toBeInTheDocument();
  });
});

describe("profile form: trust authorities", () => {
  const stores = [builtin, acme, { ...acme, id: "22222222-2222-4222-8222-222222222222", name: "Laboratoire - PKI de test", active: false }];
  it("selects private stores by identifier, never implicitly", async () => {
    responses["GET /trust-stores"] = stores;
    const setCert = vi.fn();
    wrap(<TrustAuthorities cert={{ trust: { enabled: true } }} setCert={setCert} />);
    const box = await screen.findByRole("checkbox", { name: /Client A - PKI interne/ });
    expect(box).not.toBeChecked();
    expect(screen.getByRole("checkbox", { name: /Built-in public authorities/ })).toBeChecked();
    expect(screen.getByRole("checkbox", { name: /Laboratoire/ })).toBeDisabled(); // inactive and not selected
    fireEvent.click(box);
    expect(setCert).toHaveBeenCalledWith({ trust: { enabled: true, private_stores: [acme.id] } });
  });
  it("unselecting removes the key so that the profile stays as it was", async () => {
    responses["GET /trust-stores"] = stores;
    const setCert = vi.fn();
    wrap(<TrustAuthorities cert={{ trust: { enabled: true, private_stores: [acme.id] } }} setCert={setCert} />);
    const box = await screen.findByRole("checkbox", { name: /Client A - PKI interne/ });
    expect(box).toBeChecked();
    fireEvent.click(box);
    expect(setCert).toHaveBeenCalledWith({ trust: { enabled: true } });
  });
  it("turns the built-in authorities off and says when no private store exists", async () => {
    responses["GET /trust-stores"] = [builtin];
    const setCert = vi.fn();
    wrap(<TrustAuthorities cert={{ trust: { enabled: true } }} setCert={setCert} />);
    fireEvent.click(await screen.findByRole("checkbox", { name: /Built-in public authorities/ }));
    expect(setCert).toHaveBeenCalledWith({ trust: { enabled: true, public_store: { enabled: false } } });
    expect(screen.getByText(/No private trust store available/)).toBeInTheDocument();
  });
});

describe("results: PKI trust", () => {
  const endpoint = (port: string, certificate: Record<string, unknown>, tls_checks: unknown[] = []): Endpoint => ({ endpoint_id: `10.0.0.1:${port}/tcp`, hostname: "intranet.acme.local", ip_address: "10.0.0.1", port, grade: "A", compliance_status: "compliant", highest_severity: "", tls_versions: ["TLS 1.3"], certificate: certificate as Endpoint["certificate"], errors: [], untested_checks: [], tls_checks: tls_checks as Endpoint["tls_checks"] });
  const store = { id: acme.id, name: "Client A - PKI interne", version: 2, content_sha256: "ab".repeat(32), anchors: ["CN=ACME-Root-CA"], intermediate_count: 1 };
  it("separates the chain verdict from the name, the certificate and the revocation", () => {
    wrap(<PkiTrust stores={[store]} endpoints={[
      endpoint("8470", { trust_classification: "PRIVATE_TRUSTED", trusted_by: ["Client A - PKI interne (v2)"], trust_anchor: "CN=ACME-Root-CA", status: "Valid", remaining_days: 200, revocation_status: "Revoked" }, [{ check_id: "hostname_san", status: "FAIL", message: "" }]),
      endpoint("8471", { trust_classification: "UNTRUSTED", trusted_by: [], trust_store_results: [{ store_id: "x", store_name: "Client A - PKI interne (v2)", store_type: "inline", status: "untrusted", validation_error: "unable to get local issuer certificate" }] }),
      endpoint("8472", { trust_classification: "PUBLIC_TRUSTED", trusted_by: ["TLS Scan Public Web PKI"], trust_anchor: "CN=ISRG Root X1" }),
    ]} />);
    expect(screen.getByText(/does not say that the name matches/)).toBeInTheDocument();
    expect(screen.getByText("Client A - PKI interne")).toBeInTheDocument();
    expect(screen.getByText(/SHA-256 abababababababab/)).toBeInTheDocument();
    expect(screen.getByText("Private authority")).toBeInTheDocument();
    expect(screen.getByText("Not trusted")).toBeInTheDocument();
    expect(screen.getByText("Public authority")).toBeInTheDocument();
    expect(screen.getByText("FAIL")).toBeInTheDocument();           // name check shown next to a trusted chain
    expect(screen.getByText("Revoked")).toBeInTheDocument();        // never hidden by the chain verdict
    expect(screen.getByText(/unable to get local issuer certificate/)).toBeInTheDocument();
    expect(screen.getAllByText("Not tested").length).toBeGreaterThan(0); // unknown stays unknown
  });
  it("renders nothing for scans from before the feature", () => {
    const { container } = wrap(<PkiTrust stores={[]} endpoints={[endpoint("443", { subject: "x" })]} />);
    expect(container).toBeEmptyDOMElement();
  });
});
