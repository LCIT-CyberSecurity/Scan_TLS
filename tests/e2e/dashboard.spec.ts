import { expect, test } from "@playwright/test";
import { DEMO, login } from "./helpers";

test("dashboard: compliance KPIs, charts and watch points, without horizontal overflow on a phone", async ({ page }) => {
  await login(page, "user@crashtest.example.com", DEMO);
  for (const title of [/^TLS compliance$/, /^Non-compliant endpoints$/, /^Critical and high findings$/, /^Certificates to watch$/, /^Compliance breakdown$/, /^Compliance over time$/, /^Priority watch points$/, /^Evolution between two dates$/]) {
    await expect(page.getByText(title).first()).toBeVisible();
  }
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.getByText(/^Scan activity$/)).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
});

test("dashboard: the evolution card compares two dates for the selected scan definition", async ({ page }) => {
  await login(page, "operator@crashtest.example.com", DEMO);
  await expect(page.getByText(/^Evolution between two dates$/)).toBeVisible();
  await page.getByLabel("From").fill("2000-01-01");
  await page.getByLabel("To", { exact: true }).fill("2000-01-31");
  await expect(page.getByText("No finished scan of this scan definition up to that date.")).toBeVisible();
  await page.getByLabel("From").fill(new Date(Date.now() - 365 * 86400000).toISOString().slice(0, 10));
  await page.getByLabel("To", { exact: true }).fill(new Date().toISOString().slice(0, 10));
  await page.screenshot({ path: "results/dashboard-evolution.png", fullPage: true });
});
