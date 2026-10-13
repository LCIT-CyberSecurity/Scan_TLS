import { expect, test } from "@playwright/test";
import { ADMIN, DEMO, login } from "./helpers";

// Needs the lab DNS server of the CrashTest stack (tests/lab/dns): its address is given by E2E_LAB_DNS.
const LAB_DNS = process.env.E2E_LAB_DNS ?? "";
test.skip(!LAB_DNS, "E2E_LAB_DNS (address of the lab DNS server) is required");
test.describe.configure({ mode: "serial" });

test("admin declares the lab DNS server, then an operator discovers, selects and imports in one operation", async ({ browser }) => {
  const adminPage = await (await browser.newContext({ ignoreHTTPSErrors: true, locale: "en-US" })).newPage();
  await login(adminPage, "admin", ADMIN);
  await adminPage.getByRole("link", { name: "Administration", exact: true }).first().click();
  await adminPage.getByRole("tab", { name: "Settings" }).click();
  await adminPage.getByLabel(/DNS servers a discovery may be pointed at/).fill(LAB_DNS);
  await adminPage.locator(".card", { has: adminPage.getByLabel(/DNS servers a discovery may be pointed at/) }).getByRole("button", { name: "Save" }).click();
  await expect(adminPage.getByText("Saved.")).toBeVisible();

  const page = await (await browser.newContext({ ignoreHTTPSErrors: true, locale: "en-US" })).newPage();
  await login(page, "operator@crashtest.example.com", DEMO);
  await page.getByRole("link", { name: /Targets/ }).click();
  await page.getByRole("button", { name: "DNS discovery" }).click();
  const dialog = page.getByRole("dialog");

  // step 1: fast mode has no server option, advanced does and offers only what the administrator declared
  await dialog.getByLabel("Domain", { exact: true }).fill("client.test");
  await expect(dialog.getByText("Advanced options")).toHaveCount(0);
  await dialog.getByLabel(/^Mode/).selectOption("advanced");
  const server = dialog.getByLabel(/^DNS server to query/);
  await expect(server.locator("option")).toHaveText(["Resolver configured on the worker", LAB_DNS + ":53"]);
  await server.selectOption(LAB_DNS + ":53");
  await dialog.getByLabel(/I confirm that I am authorised/).check();
  await dialog.getByRole("button", { name: "Start discovery" }).click();

  // steps 2-3: names consolidated from the zone transfer, with the transfer reported per server
  await expect(dialog.getByText("srv01.client.test")).toBeVisible({ timeout: 90_000 });
  await dialog.getByText("Zone transfer, per server").click();
  await expect(dialog.getByText("Transfer accepted")).toBeVisible();
  await expect(dialog.getByText(/ns1\.client\.test/).first()).toBeVisible();
  await expect(dialog.getByLabel("mx.partner.example")).toBeDisabled();            // outside the domain: never selectable
  await dialog.getByLabel(/^Inventory/).selectOption("NEW");
  await expect(dialog.getByText("gitlab.client.test")).toBeVisible();
  await dialog.getByRole("button", { name: "Select the new ones" }).click();
  await expect(dialog.getByText(/\d+ selected/)).not.toHaveText("0 selected");

  // step 4: exact plan before anything changes, then one grouped operation
  await dialog.getByRole("button", { name: /Review the selection/ }).click();
  await expect(dialog.getByText(/\d+ new target\(s\) will be created/)).toBeVisible();
  await expect(dialog.getByText("No scan is started and no scan definition is modified.")).toBeVisible();
  const name = `client-dns-${Date.now()}`;
  await dialog.getByLabel(/^Group/).selectOption("new");
  await dialog.getByLabel("New group name").fill(name);
  await dialog.getByRole("button", { name: "Add / Enrich the targets" }).click();
  await expect(dialog.getByText(/Done: \d+ created/)).toBeVisible();
  await dialog.getByRole("button", { name: "Close" }).last().click();

  await page.getByRole("tab", { name: "Targets" }).click();
  await expect(page.getByRole("cell", { name: "gitlab.client.test" })).toBeVisible();
  const groups = await (await page.request.get("/api/target-groups")).json();
  expect(groups.find((g: { name: string }) => g.name === name).target_ids.length).toBeGreaterThanOrEqual(4);

  // a second discovery sees them as existing, and nothing was scanned
  await page.getByRole("button", { name: "DNS discovery" }).click();
  const again = page.getByRole("dialog");
  await again.getByLabel("Domain", { exact: true }).fill("client.test");
  await again.getByLabel(/^Mode/).selectOption("advanced");
  await again.getByLabel(/^DNS server to query/).selectOption(LAB_DNS + ":53");
  await again.getByLabel(/I confirm that I am authorised/).check();
  await again.getByRole("button", { name: "Start discovery" }).click();
  await expect(again.getByText("srv01.client.test")).toBeVisible({ timeout: 90_000 });
  await again.getByLabel(/^Inventory/).selectOption("EXISTING");
  await expect(again.getByText("srv01.client.test")).toBeVisible();
  await page.screenshot({ path: "results/dns-discovery-results.png", fullPage: true });
});

test("the wizard works on a phone and in dark mode without horizontal scrolling", async ({ browser }) => {
  for (const colorScheme of ["light", "dark"] as const) {
    const context = await browser.newContext({ ignoreHTTPSErrors: true, locale: "en-US", viewport: { width: 390, height: 800 }, colorScheme });
    const page = await context.newPage();
    await login(page, "operator@crashtest.example.com", DEMO);
    await page.goto("/targets");
    await page.getByRole("button", { name: "DNS discovery" }).click();
    const dialog = page.getByRole("dialog");
    await expect(dialog.getByLabel("Domain", { exact: true })).toBeVisible();
    await dialog.getByLabel(/^Mode/).selectOption("advanced");
    const overflow = await dialog.evaluate((el) => el.scrollWidth - el.clientWidth);
    expect(overflow, `${colorScheme}: dialog overflows horizontally`).toBeLessThanOrEqual(1);
    await page.screenshot({ path: `results/dns-wizard-${colorScheme}-phone.png` });
    await context.close();
  }
});

test("the DNS discoveries tab keeps the history: reopen the results, nothing is relaunched", async ({ browser }) => {
  const page = await (await browser.newContext({ ignoreHTTPSErrors: true, locale: "en-US" })).newPage();
  await login(page, "operator@crashtest.example.com", DEMO);
  await page.getByRole("link", { name: /Targets/ }).click();
  await page.getByRole("tab", { name: "DNS discoveries" }).click();
  const row = page.getByRole("row", { name: /client\.test/ }).first();
  await expect(row.getByText("Done")).toBeVisible();
  await expect(row.getByText(/zone transfer accepted/)).toBeVisible();
  await row.getByRole("button", { name: "Open" }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByText("srv01.client.test")).toBeVisible({ timeout: 30_000 });
  await dialog.getByRole("button", { name: "Select all (current filter)" }).click();
  await expect(dialog.getByText(/\d+ selected/)).not.toHaveText("0 selected");
  await page.screenshot({ path: "results/dns-discoveries-tab.png", fullPage: true });
});

test("from the discovery to a scan: the names go into a group and a new scan, and read as covered afterwards", async ({ browser }) => {
  const page = await (await browser.newContext({ ignoreHTTPSErrors: true, locale: "en-US" })).newPage();
  await login(page, "operator@crashtest.example.com", DEMO);
  await page.getByRole("link", { name: /Targets/ }).click();
  await page.getByRole("tab", { name: "DNS discoveries" }).click();
  await page.getByRole("row", { name: /client\.test/ }).first().getByRole("button", { name: "Open" }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByText("srv01.client.test")).toBeVisible({ timeout: 30_000 });
  await dialog.getByRole("button", { name: "Select all (current filter)" }).click();
  await dialog.getByRole("button", { name: /Review the selection/ }).click();

  // a scan scans a group: choosing "new scan" proposes the group, and the scan is created without being launched
  const scanName = `discovered-${Date.now()}`;
  await dialog.getByLabel("Scan", { exact: true }).selectOption("new");
  await expect(dialog.getByLabel("New group name")).toHaveValue(/Discovery client\.test/);
  await dialog.getByLabel("Scan name").fill(scanName);
  await dialog.getByLabel(/^Profile/).selectOption({ label: "Lab - HTTPS only" });
  await dialog.locator(".check-list-box").last().locator("label").first().locator("input").check();
  await expect(dialog.getByText(new RegExp(`The scan “${scanName}” will be created \\(not launched\\)`))).toBeVisible();
  await expect(dialog.getByText("No scan is started: you launch it yourself from Scans.")).toBeVisible();
  const confirm = dialog.getByLabel(/Also apply the tags, SI and group/);
  if (await confirm.count()) await confirm.check();              // targets imported by the first test already exist: joining the group is a confirmed addition
  await dialog.getByRole("button", { name: "Add / Enrich the targets" }).click();
  await expect(dialog.getByText(/Done: \d+ created/)).toBeVisible();
  await dialog.getByRole("button", { name: "Close" }).last().click();

  const definitions = await (await page.request.get("/api/scan-definitions")).json();
  const created = definitions.find((d: { name: string }) => d.name === scanName);
  expect(created.group_ids).toHaveLength(1);
  expect(created.target_ids).toHaveLength(0);
  const runs = await (await page.request.get("/api/scan-runs", { params: { definition_id: created.id } })).json();
  expect(runs).toHaveLength(0);                                   // nothing was launched

  // reopening the discovery: the names are now reported as covered by that scan, and left out of the bulk selection
  await page.getByRole("row", { name: /client\.test/ }).first().getByRole("button", { name: "Open" }).click();
  await expect(dialog.getByText("srv01.client.test")).toBeVisible({ timeout: 30_000 });
  await expect(dialog.getByText(/name\(s\) already covered by a scan/)).toBeVisible();
  await expect(dialog.getByText(scanName).first()).toBeVisible();
  await dialog.getByRole("button", { name: "Select all (current filter)" }).click();
  await expect(dialog.getByText(/\d+ selected/)).toHaveText(/^(0|[1-3]) selected$/);   // the covered names are not in it (mx.partner.example is out of scope)
  await page.screenshot({ path: "results/dns-discovery-coverage.png", fullPage: true });
});
