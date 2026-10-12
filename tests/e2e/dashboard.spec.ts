import { expect, test } from "@playwright/test";
import { DEMO, login } from "./helpers";

test("dashboard: compliance KPIs, charts and watch points, without horizontal overflow on a phone", async ({ page }) => {
  await login(page, "user@crashtest.example.com", DEMO);
  for (const title of [/^TLS compliance$/, /^Non-compliant endpoints$/, /^Critical and high findings$/, /^Certificates to watch$/, /^Compliance breakdown$/, /^Compliance over time$/, /^Priority watch points$/]) {
    await expect(page.getByText(title).first()).toBeVisible();
  }
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.getByText(/^Scan activity$/)).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
});
