import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { expect, test, type Page } from "@playwright/test";
import { ADMIN, login } from "./helpers";

const artifacts = join(process.cwd(), "../../artifacts/network-map");

async function saveScreenshot(page: Page, project: string, view: string, width: number, height: number) {
  mkdirSync(artifacts, { recursive: true });
  await page.setViewportSize({ width, height });
  await page.screenshot({ path: join(artifacts, `${project}-${view}-${width}x${height}.png`), fullPage: true });
}

async function searchAndSelect(page: Page, term: string, result: RegExp) {
  const search = page.getByPlaceholder("Search systems, zones, hosts or IPs");
  await search.fill(term);
  await search.press("Enter");
  const match = page.getByRole("button", { name: result }).last();
  await expect(match).toBeVisible();
  await match.click();
}

test("Chromium: real TLS scan, progressive map navigation and responsive captures", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "Chromium", "The scan is launched once; Chrome performs a separate rendering smoke check.");
  await login(page, "admin", ADMIN);
  await page.goto("/scans");
  await page.getByRole("tab", { name: "Definitions" }).click();
  await page.getByRole("row", { name: /Lab - full scenario scan \(ANSSI\)/ }).getByRole("button", { name: "Run" }).click();
  await expect(page.getByText(/^(Completed|Partially completed)$/).first()).toBeVisible({ timeout: 240_000 });

  await page.goto("/scans/map");
  await expect(page.locator(".network-map-canvas canvas").first()).toBeVisible({ timeout: 30_000 });
  await expect(page.getByRole("group", { name: "Map overview" })).toBeVisible();

  for (const size of [{ width: 1920, height: 1080 }, { width: 1440, height: 900 }, { width: 1366, height: 768 }]) {
    await saveScreenshot(page, testInfo.project.name.toLowerCase(), "global", size.width, size.height);
  }

  await searchAndSelect(page, "Production", /Production\s+si/i);
  await page.getByRole("button", { name: "Network architecture" }).click();
  await expect(page.getByRole("button", { name: "Network architecture" })).toHaveAttribute("aria-pressed", "true");
  for (const size of [{ width: 1920, height: 1080 }, { width: 1440, height: 900 }, { width: 1366, height: 768 }]) {
    await saveScreenshot(page, testInfo.project.name.toLowerCase(), "si-zones", size.width, size.height);
  }

  await searchAndSelect(page, "Public DMZ", /Public DMZ\s+zone/i);
  await expect(page.locator(".network-map-crumbs")).toContainText("Public DMZ");
  await searchAndSelect(page, "lab-tls", /lab-tls/i);
  await expect(page.getByRole("complementary", { name: "Host exposure" })).toBeVisible();
  await expect(page.getByRole("complementary").getByText("Last scan")).toBeVisible();
  for (const size of [{ width: 1920, height: 1080 }, { width: 1440, height: 900 }, { width: 1366, height: 768 }]) {
    await saveScreenshot(page, testInfo.project.name.toLowerCase(), "host-exposure", size.width, size.height);
  }
});

test("Google Chrome: map loads and displays its actual graph canvas", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "Google Chrome", "Chromium runs the full journey and capture matrix.");
  await login(page, "admin", ADMIN);
  await page.goto("/scans/map");
  await expect(page.locator(".network-map-canvas canvas").first()).toBeVisible({ timeout: 30_000 });
  await expect(page.getByRole("group", { name: "Map overview" })).toBeVisible();
  await saveScreenshot(page, "chrome", "global", 1440, 900);
  await searchAndSelect(page, "Production", /Production\s+si/i);
  await page.getByRole("button", { name: "Network architecture" }).click();
  await saveScreenshot(page, "chrome", "si-zones", 1440, 900);
  await searchAndSelect(page, "lab-tls", /lab-tls/i);
  await expect(page.getByRole("complementary", { name: "Host exposure" })).toBeVisible();
  await saveScreenshot(page, "chrome", "host-exposure", 1440, 900);
});
