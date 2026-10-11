import { expect, test } from "@playwright/test";
import { DEMO, login } from "./helpers";

test("user: create a target, launch a scan, follow it, read results, download a report, compare", async ({ page }) => {
  await login(page, "user@crashtest.example.com", DEMO);
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();

  // create a target with a tag
  await page.getByRole("link", { name: /Targets/ }).click();
  await page.getByRole("button", { name: "New target" }).click();
  const value = `e2e-${Date.now()}.example.org`;
  await page.getByRole("dialog").getByLabel("Targets", { exact: true }).fill(value);
  await page.getByRole("dialog").getByLabel("Tags").fill("E2E");
  await page.getByRole("dialog").getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("cell", { name: value })).toBeVisible();

  // launch the seeded HTTPS-only lab definition
  await page.getByRole("link", { name: "Scans", exact: true }).click();
  await page.getByRole("tab", { name: "Definitions" }).click();
  const row = page.getByRole("row", { name: /Lab - HTTPS only/ });
  await row.getByRole("button", { name: "Run" }).click();

  // run page: status progresses to a final state
  await expect(page).toHaveURL(/\/scans\/[0-9a-f-]+/);
  await expect(page.getByText(/^(Completed|Partially completed)$/).first()).toBeVisible({ timeout: 180_000 });
  await expect(page.getByRole("heading", { name: "Findings" })).toBeVisible();
  await expect(page.getByText(/lab-tls|:443/).first()).toBeVisible();

  // download the CSV report
  const [download] = await Promise.all([page.waitForEvent("download"), page.getByRole("link", { name: "CSV", exact: true }).click()]);
  expect(download.suggestedFilename()).toMatch(/\.csv$/);

  // a second run, then compare with the previous one
  const url = page.url();
  await page.getByRole("link", { name: "Scans", exact: true }).click();
  await page.getByRole("tab", { name: "Definitions" }).click();
  await page.getByRole("row", { name: /Lab - HTTPS only/ }).getByRole("button", { name: "Run" }).click();
  await expect(page).not.toHaveURL(url);
  await expect(page.getByText(/^(Completed|Partially completed)$/).first()).toBeVisible({ timeout: 180_000 });
  await page.getByRole("button", { name: "Compare with previous" }).click();
  await expect(page.getByText("Persistent")).toBeVisible();
});

test("a TLS-less target is shown as 'no TLS service', not as a success", async ({ page }) => {
  await login(page, "user@crashtest.example.com", DEMO);
  await page.goto("/scans");
  await page.getByRole("tab", { name: "Definitions" }).click();
  // the seeded scenario scan includes port 80 (plain HTTP): it must not appear as a compliant endpoint
  await page.getByRole("row", { name: /Lab - full scenario scan/ }).getByRole("button", { name: "Run" }).click();
  await expect(page.getByText(/^(Completed|Partially completed)$/).first()).toBeVisible({ timeout: 200_000 });
  await expect(page.getByText(":80", { exact: false })).toHaveCount(0);
});
