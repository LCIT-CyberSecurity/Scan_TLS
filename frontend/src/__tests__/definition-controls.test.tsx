// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "../test-utils";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import type { Definition, Versioned } from "../api/types";
import { I18nProvider } from "../i18n";

const published = (version = 1) => [{ id: `v${version}`, version, status: "published", content: {} }];
const standard = { id: "p-std", name: "Standard", description: "", technology: "tls", archived: false, versions: published() } as unknown as Versioned;
const generic = { id: "p-gen", name: "Multi", description: "", technology: "generic", archived: false, versions: published() } as unknown as Versioned;
const anssi = { id: "pol-tls", name: "ANSSI", description: "", technology: "tls", archived: false, versions: published() } as unknown as Versioned;
const sshPolicy = { id: "pol-ssh", name: "SSH baseline", description: "", technology: "ssh", archived: false, versions: published() } as unknown as Versioned;
const homeScan = {
  id: "d1", name: "home scan", description: "", owner_id: "u", profile_id: "p-std", control_type: "tls", enabled_controls: null,
  report_template_id: null, policy_mode: "strict_all", tags: [], si_ids: [], target_ids: ["t1"], group_ids: [], policy_ids: ["pol-tls"],
} as unknown as Definition;

const catalog = vi.hoisted(() => ({ generic: [] as unknown[], ssh: [] as unknown[] }));
const calls = vi.hoisted(() => [] as { path: string; options?: { method?: string; body?: unknown } }[]);
vi.mock("../auth/AuthContext", () => ({ useAuth: () => ({ user: { id: "u", role: "USER" }, atLeast: (role: string) => role === "USER" || role === "AUDITOR" }) }));
vi.mock("../api/client", async (original) => ({
  ...(await original<object>()),
  api: vi.fn(async (path: string, options?: { method?: string; body?: unknown }) => {
    calls.push({ path, options });
    if (path === "/profiles") return [standard];
    if (path === "/profiles?technology=generic") return catalog.generic;
    if (path === "/policies") return [anssi];
    if (path === "/policies?technology=ssh") return catalog.ssh;
    if (path === "/targets") return [{ id: "t1", value: "example.org", name: "", ports: "443" }];
    if (options?.method === "PUT") return {};
    return [];
  }),
}));
import { DefinitionDialog } from "../pages/Scans";

function edit() {
  const onSaved = vi.fn();
  render(<I18nProvider initial="en"><MemoryRouter><DefinitionDialog initial={homeScan} onClose={vi.fn()} onSaved={onSaved} /></MemoryRouter></I18nProvider>);
  return onSaved;
}
/** The checkbox of a policy or target, found by the exact label text (several spans make regex names ambiguous). */
const box = (label: string) => screen.getByText(label).closest("label")!.querySelector("input") as HTMLInputElement;
const saves = () => calls.filter((call) => call.options?.method === "PUT");

beforeEach(() => { calls.length = 0; catalog.generic = []; catalog.ssh = []; });
afterEach(cleanup);

describe("scan definition technologies (LST-33)", () => {
  it("explains what is missing instead of sending an empty profile when SSH is added", async () => {
    edit();
    expect(await screen.findByRole("option", { name: "Standard" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("checkbox", { name: "SSH (ssh-audit)" }));
    expect(await screen.findByText(/No published multi-technology profile/)).toBeInTheDocument();
    expect(await screen.findByText("No published SSH policy. Create and publish one in Policies to run this check.")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Choose a scan profile.");
    expect(saves()).toHaveLength(0);
  });

  it("keeps the policies that still apply and saves TLS + SSH with a generic profile", async () => {
    catalog.generic = [generic];
    catalog.ssh = [sshPolicy];
    const onSaved = edit();
    fireEvent.click(await screen.findByRole("checkbox", { name: "SSH (ssh-audit)" }));
    const profile = await screen.findByRole("combobox", { name: "Scan profile" });
    await screen.findByRole("option", { name: "Multi" });
    expect(box("ANSSI")).toBeChecked();          // the TLS policy survives the toggle
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Choose a scan profile.");
    fireEvent.change(profile, { target: { value: "p-gen" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Select a policy for each enabled technology: SSH.");
    fireEvent.click(box("SSH baseline"));
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(saves()).toHaveLength(1));
    expect(saves()[0].options?.body).toMatchObject({ profile_id: "p-gen", enabled_controls: ["tls", "ssh"], policy_ids: ["pol-tls", "pol-ssh"] });
    expect(onSaved).toHaveBeenCalled();
  });

  it("drops an SSH policy when SSH is unticked again", async () => {
    catalog.generic = [generic];
    catalog.ssh = [sshPolicy];
    edit();
    const ssh = await screen.findByRole("checkbox", { name: "SSH (ssh-audit)" });
    fireEvent.click(ssh);
    await screen.findByText("SSH baseline");
    fireEvent.click(box("SSH baseline"));
    fireEvent.click(ssh);
    await waitFor(() => expect(screen.queryByText("SSH baseline")).toBeNull());
    expect(box("ANSSI")).toBeChecked();
  });
});
