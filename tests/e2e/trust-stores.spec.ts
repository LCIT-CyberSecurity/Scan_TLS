import { expect, request, test, type APIRequestContext, type Page } from "@playwright/test";
import { ADMIN, DEMO, login } from "./helpers";

// Private PKI scenario of the lab (tests/lab): ACME Root CA -> Issuing CA -> intranet.acme.local on 8500 (chain sent) and 8501 (issuing CA not sent).
const base = () => process.env.E2E_BASE_URL ?? "https://localhost:5100";
const labPort = process.env.E2E_LAB_PORT ?? "5130";
const labUrl = (file: string) => `http://${new URL(base()).hostname}:${labPort}/pki/${file}`;
const stamp = Date.now();
const STORE = `ACME PKI e2e ${stamp}`;
const PROFILE = `acme-profile-${stamp}`;

async function apiLogin(username: string, password: string): Promise<{ api: APIRequestContext; csrf: string }> {
  const api = await request.newContext({ baseURL: base(), ignoreHTTPSErrors: true });
  const response = await api.post("/api/auth/login", { data: { username, password } });
  expect(response.ok()).toBeTruthy();
  return { api, csrf: (await response.json()).csrf_token };
}

async function fetchLabFile(name: string): Promise<Buffer> {
  const response = await fetch(labUrl(name));
  expect(response.ok, `${labUrl(name)} must be reachable (lab-tls publishes /pki)`).toBeTruthy();
  return Buffer.from(await response.arrayBuffer());
}

async function openTrustTab(page: Page) {
  await page.getByRole("link", { name: "Administration", exact: true }).first().click();
  await page.getByRole("tab", { name: "Trust authorities" }).click();
}

test.describe.configure({ mode: "serial" });

test("admin: the built-in store is read-only, a private store is created from a CA file, bad files are refused", async ({ page }) => {
  await login(page, "admin", ADMIN);
  await openTrustTab(page);
  const builtin = page.getByRole("row", { name: /TLS Scan Public Web PKI/ });
  await expect(builtin).toBeVisible();
  await expect(builtin.getByText("Built-in public")).toBeVisible();
  await expect(builtin.getByRole("button")).toHaveCount(0);

  await page.getByRole("button", { name: "New trust store" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Name", { exact: true }).fill(STORE);

  // a private key and a PKCS#12 bundle are refused with an explicit message, and nothing can be created from them
  await dialog.getByLabel(/CA certificate files/).setInputFiles([
    { name: "key.pem", mimeType: "text/plain", buffer: await fetchLabFile("private-key-sample.pem") },
    { name: "bundle.p12", mimeType: "application/octet-stream", buffer: await fetchLabFile("bundle.p12") },
  ]);
  await expect(dialog.getByText(/private keys are refused/)).toBeVisible();
  await expect(dialog.getByText(/binary content is not supported/)).toBeVisible();
  await dialog.getByRole("button", { name: "Create and import" }).click();
  await expect(dialog.getByRole("alert").first()).toBeVisible();

  // the Root CA and the issuing CA: roles are shown before anything is stored
  await dialog.getByLabel(/CA certificate files/).setInputFiles([
    { name: "root.crt", mimeType: "application/x-x509-ca-cert", buffer: await fetchLabFile("ACME-Root-CA.crt") },
    { name: "issuing.cer", mimeType: "application/x-x509-ca-cert", buffer: await fetchLabFile("ACME-Issuing-CA.crt") },
  ]);
  await expect(dialog.getByText("Root CA (trust anchor)")).toBeVisible();
  await expect(dialog.getByText("Intermediate CA", { exact: true })).toBeVisible();
  await dialog.getByRole("button", { name: "Create and import" }).click();

  // the detail opens on the new store: v1, two certificates, the profile list is empty
  const detail = page.getByRole("dialog");
  await expect(detail.getByRole("heading", { name: STORE })).toBeVisible();
  await expect(detail.getByText("v1").first()).toBeVisible();
  await expect(detail.getByText("CN=ACME-Root-CA").first()).toBeVisible();
  await expect(detail.getByText("No profile uses this store.")).toBeVisible();
  await detail.getByRole("button", { name: "Details" }).first().click();
  await expect(detail.getByText("SHA-256 fingerprint")).toBeVisible();
  await detail.getByRole("button", { name: "Close" }).last().click();
  await expect(page.getByRole("row", { name: new RegExp(STORE) }).getByText("Private")).toBeVisible();

  // the audit trail records the creation, without any certificate content
  await page.getByRole("tab", { name: "Audit log" }).click();
  await expect(page.getByRole("cell", { name: "trust_store.create" }).first()).toBeVisible();
});

test("operator: the profile selects the private store explicitly, saves and publishes it", async ({ page }) => {
  await login(page, "operator@crashtest.example.com", DEMO);
  await page.getByRole("link", { name: "Profiles" }).click();
  await page.getByRole("tab", { name: "Scan profiles" }).click();
  await page.getByRole("button", { name: "New", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Name", { exact: true }).fill(PROFILE);
  await dialog.getByLabel("Ports", { exact: true }).fill("8500,8501");
  const group = dialog.getByRole("group", { name: "Private trust stores" });
  await expect(group.getByRole("checkbox", { name: /Built-in public authorities/ })).toBeChecked();
  const store = group.getByRole("checkbox", { name: new RegExp(STORE) });
  await expect(store).not.toBeChecked(); // never implicit
  await store.check();
  await dialog.getByRole("button", { name: "Save" }).click();
  const row = page.getByRole("row", { name: new RegExp(PROFILE) });
  await expect(row).toBeVisible();
  await row.getByRole("button", { name: "Publish" }).click();
  await expect(row.getByText("v1").first()).toBeVisible();

  const profiles = await (await page.request.get("/api/profiles")).json();
  const saved = profiles.find((p: { name: string }) => p.name === PROFILE);
  expect(saved.versions[0].content.checks.certificate.trust.private_stores).toHaveLength(1);
  // an existing seeded profile is untouched
  const seeded = profiles.find((p: { name: string }) => p.name !== PROFILE);
  expect(JSON.stringify(seeded.versions[0].content)).not.toContain("private_stores");
});

test("user: the scan result tells which authority validated each certificate, and keeps the other controls apart", async ({ page }) => {
  const operator = await apiLogin("operator@crashtest.example.com", DEMO);
  const headers = { "x-csrf-token": operator.csrf };
  const profile = (await (await operator.api.get("/api/profiles")).json()).find((p: { name: string }) => p.name === PROFILE);
  const policy = (await (await operator.api.get("/api/policies")).json())[0];
  const target = await operator.api.post("/api/targets", { headers, data: { value: "intranet.acme.local", ports: "" } });
  const targetId = target.ok() ? (await target.json()).id : (await (await operator.api.get("/api/targets", { params: { q: "intranet.acme.local" } })).json())[0].id;
  const definition = await (await operator.api.post("/api/scan-definitions", { headers, data: { name: `acme-scan-${stamp}`, target_ids: [targetId], policy_ids: [policy.id], profile_id: profile.id } })).json();
  const run = await (await operator.api.post(`/api/scan-definitions/${definition.id}/run`, { headers })).json();

  await login(page, "operator@crashtest.example.com", DEMO);
  await page.goto(`/scans/${run.run_id}`);
  await expect(page.getByText(/^(Completed|Partially completed)$/).first()).toBeVisible({ timeout: 200_000 });
  const card = page.locator(".card", { has: page.getByRole("heading", { name: "PKI trust" }) });
  await expect(card).toBeVisible();
  await expect(card.getByText(/does not say that the name matches/)).toBeVisible();
  await expect(card.getByText(new RegExp(`${STORE}.*v1`)).first()).toBeVisible();   // the exact store version used by the scan
  const full = card.getByRole("row", { name: /:8500/ });
  await expect(full.getByText("Private authority")).toBeVisible();
  await expect(full).toContainText("CN=ACME-Root-CA");
  // 8501 does not send the issuing CA: it is the administered intermediate of the store that legitimately completes the chain (the anchor stays the Root CA)
  const incomplete = card.getByRole("row", { name: /:8501/ });
  await expect(incomplete.getByText("Private authority")).toBeVisible();
  await expect(incomplete).toContainText("CN=ACME-Root-CA");
  await page.screenshot({ path: "results/pki-trust-light.png", fullPage: true });

  // the same store, changed later by an administrator, does not alter this historical scan
  const admin = await apiLogin("admin", ADMIN);
  const stores = await (await admin.api.get("/api/admin/trust-stores")).json();
  const id = stores.find((s: { name: string }) => s.name === STORE).id;
  const globex = await fetchLabFile("Globex-Root-CA.crt");
  const changed = await admin.api.post(`/api/admin/trust-stores/${id}/versions`, { headers: { "x-csrf-token": admin.csrf }, data: { base: "empty", files: [{ filename: "g.crt", content_b64: globex.toString("base64") }] } });
  expect(changed.status()).toBe(201);
  await page.reload();
  await expect(card.getByRole("row", { name: /:8500/ }).getByText("Private authority")).toBeVisible();
  await expect(card.getByText(new RegExp(`${STORE}.*v1`)).first()).toBeVisible();

  // ...while a new scan with the same profile uses v2 (another customer's Root CA only): nothing is trusted anymore
  const rerun = await (await operator.api.post(`/api/scan-definitions/${definition.id}/run`, { headers })).json();
  await page.goto(`/scans/${rerun.run_id}`);
  await expect(page.getByText(/^(Completed|Partially completed)$/).first()).toBeVisible({ timeout: 200_000 });
  const newCard = page.locator(".card", { has: page.getByRole("heading", { name: "PKI trust" }) });
  await expect(newCard.getByText(new RegExp(`${STORE}.*v2`)).first()).toBeVisible();
  await expect(newCard.getByRole("row", { name: /:8500/ }).getByText("Not trusted")).toBeVisible();
  await expect(newCard.getByRole("row", { name: /:8500/ })).toContainText(/unable to get local issuer certificate|self-signed|issuer/i);
});

test("the trust authorities tab works on a phone and in dark mode, without horizontal scrolling", async ({ browser }) => {
  for (const colorScheme of ["light", "dark"] as const) {
    const context = await browser.newContext({ ignoreHTTPSErrors: true, locale: "en-US", viewport: { width: 390, height: 800 }, colorScheme });
    const page = await context.newPage();
    await login(page, "admin", ADMIN);
    if (await page.getByRole("button", { name: "Open the menu" }).isVisible()) await page.getByRole("button", { name: "Open the menu" }).click();
    await page.getByRole("link", { name: "Administration", exact: true }).first().click();
    await page.getByRole("tab", { name: "Trust authorities" }).click();
    await expect(page.getByRole("row", { name: /TLS Scan Public Web PKI/ })).toBeVisible();
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    expect(overflow, `${colorScheme}: page overflows horizontally`).toBeLessThanOrEqual(1);
    await page.screenshot({ path: `results/trust-authorities-${colorScheme}-phone.png`, fullPage: true });
    await context.close();
  }
});
