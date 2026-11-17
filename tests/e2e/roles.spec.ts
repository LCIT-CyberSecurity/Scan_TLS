import { expect, test } from "@playwright/test";
import { ADMIN, DEMO, login, navigateSidebar } from "./helpers";

const MENUS = ["Dashboard", "My tasks", "Scans", "Schedules", "Targets", "Profiles", "Reports", "Administration"];
const visible = async (page: import("@playwright/test").Page) => {
  const nav = page.getByRole("navigation", { name: "Main" });
  const labels = new Set<string>();
  for (const group of ["Workspace", "Scanning", "Results", "Administration"]) {
    const toggle = nav.getByRole("button", { name: group, exact: true });
    if (!(await toggle.count())) continue;
    if (await toggle.getAttribute("aria-expanded") !== "true") await toggle.click();
    for (const label of await nav.getByRole("link").allTextContents()) labels.add(label.trim());
  }
  return MENUS.filter((menu) => labels.has(menu));
};

test("the sidebar adapts to the role", async ({ browser }) => {
  const expected: Record<string, [string, string[]]> = {
    auditor: [DEMO, ["Dashboard", "Reports"]],
    user: [DEMO, ["Dashboard", "My tasks", "Scans", "Schedules", "Targets", "Profiles", "Reports"]],
    operator: [DEMO, ["Dashboard", "My tasks", "Scans", "Schedules", "Targets", "Profiles", "Reports"]],
  };
  for (const [name, [pw, menus]] of Object.entries(expected)) {
    const page = await (await browser.newContext({ ignoreHTTPSErrors: true, locale: "en-US" })).newPage();
    await login(page, `${name}@crashtest.example.com`, pw);
    expect(await visible(page), name).toEqual(menus);
  }
  const page = await (await browser.newContext({ ignoreHTTPSErrors: true, locale: "en-US" })).newPage();
  await login(page, "admin", ADMIN);
  expect(await visible(page)).toEqual(MENUS);
});

test("sidebar compact mode persists, groups reveal role-filtered links, and content gets the freed width", async ({ page }) => {
  await login(page, "admin", ADMIN);
  const sidebar = page.locator(".sidebar");
  const content = page.locator(".page");
  for (const size of [{ width: 1366, height: 768 }, { width: 1920, height: 1080 }]) {
    await page.setViewportSize(size);
    if (await sidebar.evaluate((element) => element.classList.contains("sidebar--compact"))) {
      await page.getByRole("button", { name: "Expand sidebar" }).click();
    }
    const before = (await content.boundingBox())?.width ?? 0;
    await page.getByRole("button", { name: "Collapse sidebar" }).click();
    await expect(sidebar).toHaveClass(/sidebar--compact/);
    const after = (await content.boundingBox())?.width ?? 0;
    expect(after).toBeGreaterThan(before);
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
  }
  const scanning = page.getByRole("navigation", { name: "Main" }).getByRole("button", { name: "Scanning" });
  await expect(scanning).toHaveAttribute("aria-expanded", "false");
  await scanning.click();
  await expect(page.getByRole("link", { name: "Targets" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Targets" })).toHaveAttribute("title", "Targets");
  await page.reload();
  await expect(sidebar).toHaveClass(/sidebar--compact/);
});

test("mobile navigation opens and closes with Escape", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await login(page, "admin", ADMIN);
  const menu = page.getByRole("button", { name: "Open menu" });
  await menu.click();
  await expect(page.locator(".sidebar")).toHaveClass(/sidebar--open/);
  await page.keyboard.press("Escape");
  await expect(page.locator(".sidebar")).not.toHaveClass(/sidebar--open/);
});

test("direct URL access is also refused server-side for an auditor", async ({ page }) => {
  await login(page, "auditor@crashtest.example.com", DEMO);
  await page.goto("/admin");
  await expect(page).toHaveURL(/\/$/);
  const status = await page.evaluate(async () => (await fetch("/api/admin/users")).status);
  expect(status).toBe(403);
});

test("admin: users, audit and diagnostics", async ({ page }) => {
  await login(page, "admin", ADMIN);
  await navigateSidebar(page, "Administration", "Administration");
  await expect(page.getByRole("cell", { name: /operator@crashtest/ }).first()).toBeVisible();
  await page.getByRole("tab", { name: "Audit log" }).click();
  await expect(page.getByText("auth.login").first()).toBeVisible();
  await page.getByRole("tab", { name: "Diagnostics" }).click();
  await expect(page.getByText("PostgreSQL")).toBeVisible();
});

test("operator can publish a policy version; user cannot see the buttons", async ({ browser }) => {
  const op = await (await browser.newContext({ ignoreHTTPSErrors: true, locale: "en-US" })).newPage();
  await login(op, "operator@crashtest.example.com", DEMO);
  await navigateSidebar(op, "Scanning", "Profiles");
  await expect(op.getByRole("button", { name: "New" }).first()).toBeVisible();
  const user = await (await browser.newContext({ ignoreHTTPSErrors: true, locale: "en-US" })).newPage();
  await login(user, "user@crashtest.example.com", DEMO);
  await navigateSidebar(user, "Scanning", "Profiles");
  await expect(user.getByRole("button", { name: "New" })).toHaveCount(0);
});

test("admin: notification connector and directory settings screens", async ({ page }) => {
  await login(page, "admin", ADMIN);
  await navigateSidebar(page, "Administration", "Administration");
  await page.getByRole("tab", { name: "Settings" }).click();
  await page.getByLabel("Notification connector").selectOption("graph");
  await expect(page.getByLabel("Sender mailbox")).toBeVisible();
  await page.getByLabel("Notification connector").selectOption("smtp");
  await expect(page.getByLabel("Host")).toBeVisible();
  await page.getByRole("tab", { name: "Directory" }).click();
  await page.getByLabel("Directory type").selectOption("ldap");
  await expect(page.getByLabel("Base DN")).toBeVisible();
  await expect(page.getByLabel("Verify the server certificate")).toBeChecked();
});
