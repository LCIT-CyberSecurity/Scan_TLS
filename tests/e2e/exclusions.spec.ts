import { expect, test } from "@playwright/test";
import { ADMIN, DEMO, login } from "./helpers";

test("an administrator sets global exclusions, a scan definition carries its own", async ({ browser }) => {
  const admin = await (await browser.newContext({ ignoreHTTPSErrors: true, locale: "en-US" })).newPage();
  await login(admin, "admin", ADMIN);
  await admin.getByRole("link", { name: "Administration", exact: true }).first().click();
  await admin.getByRole("tab", { name: "Settings" }).click();
  const box = admin.getByLabel("Exclusions (never scanned)");
  const save = admin.locator(".card", { has: box }).getByRole("button", { name: "Save" });
  await box.fill("-oN /tmp/x");
  await save.click();
  await expect(admin.getByRole("alert")).toContainText(/invalid exclusion/i);   // anything that could become an nmap option is refused
  await box.fill("decommissioned.example.org\n10.99.0.0/24\n*.legacy.example.org");
  await save.click();
  await expect(admin.getByText("Saved.")).toBeVisible();
  await admin.reload();
  await admin.getByRole("tab", { name: "Settings" }).click();
  await expect(admin.getByLabel("Exclusions (never scanned)")).toHaveValue("decommissioned.example.org\n10.99.0.0/24\n*.legacy.example.org");
  await admin.getByLabel("Exclusions (never scanned)").fill("");
  await save.click();
  await expect(admin.getByText("Saved.")).toBeVisible();

  const op = await (await browser.newContext({ ignoreHTTPSErrors: true, locale: "en-US" })).newPage();
  await login(op, "operator@crashtest.example.com", DEMO);
  await op.getByRole("link", { name: "Scans", exact: true }).click();
  await op.getByRole("button", { name: "New scan", exact: true }).click();
  const dialog = op.getByRole("dialog");
  await expect(dialog.getByLabel("Exclusions (never scanned)")).toBeVisible();
  await expect(dialog.getByText(/a wildcard \(\*\.test\.example\.org/)).toBeVisible();
});
