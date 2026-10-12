import { expect, test } from "@playwright/test";
import { DEMO, login } from "./helpers";

test("New scan: a target can be created from the dialog and is selected", async ({ page }) => {
  await login(page, "user@crashtest.example.com", DEMO);
  await page.goto("/scans");
  await page.getByRole("button", { name: /new scan|nouveau scan/i }).click();
  const host = `inline-${Date.now()}.example.org`;
  await page.getByRole("button", { name: /new target|nouvelle cible/i }).click();
  await page.getByLabel(/^(targets|cibles)$/i).fill(host);
  await page.getByRole("button", { name: /^(save|enregistrer)$/i }).last().click();
  // back in the scan dialog: the new target is listed and already ticked
  await expect(page.getByLabel(host, { exact: true })).toBeChecked();  // exact label: another entry may list the target among others
});
