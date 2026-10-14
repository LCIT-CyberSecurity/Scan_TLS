import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { expect, test, type Browser, type Page } from "@playwright/test";
import { ADMIN, login } from "./helpers";

const artifacts = join(process.cwd(), "../../artifacts/network-map");

async function saveScreenshot(page: Page, project: string, view: string, width: number, height: number) {
  mkdirSync(artifacts, { recursive: true });
  await page.waitForTimeout(350);
  await page.screenshot({ path: join(artifacts, `${project}-${view}-${width}x${height}.png`) });
}

async function waitForApplication(page: Page) {
  await expect.poll(async () => {
    const response = await page.request.get("/api/health/ready").catch(() => undefined);
    return response?.status() === 200;
  }, { timeout: 30_000 }).toBe(true);
}

async function searchAndSelect(page: Page, term: string, result: RegExp) {
  const search = page.getByPlaceholder("Search systems, zones, hosts or IPs");
  await search.fill(term);
  await search.press("Enter");
  const match = page.getByRole("button", { name: result }).last();
  await expect(match).toBeVisible();
  const graph = page.waitForResponse((response) => response.url().includes("/api/map/graph") && response.status() === 200);
  await match.click();
  await graph;
  await page.waitForTimeout(350);
}

async function selectDarkAppearance(page: Page) {
  await page.locator("details.user-menu > summary").click();
  await page.getByRole("group", { name: "Appearance" }).getByRole("button", { name: "Dark" }).click();
  await expect(page.locator("html")).toHaveAttribute("data-appearance", "dark");
}

async function captureMapAtSize(browser: Browser, project: string, size: { width: number; height: number }) {
  const context = await browser.newContext({
    baseURL: process.env.E2E_BASE_URL ?? "https://localhost:15200",
    ignoreHTTPSErrors: true,
    locale: "en-US",
    viewport: size,
  });
  try {
    const page = await context.newPage();
    page.on("pageerror", (error) => console.log(`[${project} ${size.width}] PAGEERROR ${error.stack ?? error.message}`));
    page.on("console", (message) => { if (message.type() === "error") console.log(`[${project} ${size.width}] CONSOLE ${message.text()}`); });
    await waitForApplication(page);
    await login(page, "admin", ADMIN);
    await selectDarkAppearance(page);
    await page.goto("/scans/map");
    await expect(page.locator(".network-map-canvas canvas").first()).toBeVisible({ timeout: 30_000 });
    await expect(page.getByRole("group", { name: "Map overview" })).toBeVisible();
    await saveScreenshot(page, project, "global", size.width, size.height);

    await searchAndSelect(page, "Production", /Production\s+si/i);
    const networkGraph = page.waitForResponse((response) => response.url().includes("/api/map/graph") && response.url().includes("mode=network") && response.status() === 200);
    await page.getByRole("button", { name: "Network architecture" }).click();
    await networkGraph;
    await expect(page.getByRole("button", { name: "Network architecture" })).toHaveAttribute("aria-pressed", "true");
    await saveScreenshot(page, project, "si-zones", size.width, size.height);

    await searchAndSelect(page, "Public DMZ", /Public DMZ\s+zone/i);
    await expect(page.locator(".network-map-crumbs")).toContainText("Public DMZ");
    await searchAndSelect(page, "lab-tls", /lab-tls/i);
    const detail = page.getByRole("complementary", { name: "Host exposure" });
    await expect(detail).toBeVisible();
    await expect(detail.getByText("Last scan")).toBeVisible();
    await saveScreenshot(page, project, "host-exposure", size.width, size.height);
  } finally {
    await context.close();
  }
}

test("Chromium: real TLS scan, progressive map navigation and responsive captures", async ({ page, browser }, testInfo) => {
  test.skip(testInfo.project.name !== "Chromium", "The scan is launched once; Chrome performs a separate rendering smoke check.");
  await waitForApplication(page);
  await login(page, "admin", ADMIN);
  await page.goto("/scans");
  await page.getByRole("tab", { name: "Definitions" }).click();
  await page.getByRole("row", { name: /Lab - full scenario scan \(ANSSI\)/ }).getByRole("button", { name: "Run" }).click();
  await expect(page.getByText(/^(Completed|Partially completed)$/).first()).toBeVisible({ timeout: 240_000 });

  for (const size of [{ width: 1920, height: 1080 }, { width: 1440, height: 900 }, { width: 1366, height: 768 }]) {
    await captureMapAtSize(browser, testInfo.project.name.toLowerCase(), size);
  }
});

test("Google Chrome: map loads and displays its actual graph canvas", async ({ browser }, testInfo) => {
  test.skip(testInfo.project.name !== "Google Chrome", "Chromium runs the full journey and capture matrix.");
  await captureMapAtSize(browser, "chrome", { width: 1440, height: 900 });
});
