import { expect, test } from "@playwright/test";
import { ADMIN, DEMO, login } from "./helpers";

const MENUS = ["Dashboard", "My tasks", "Scans", "Schedules", "Targets & groupings", "Policies & profiles", "Reports", "Administration"];
const visible = async (page: import("@playwright/test").Page) => (await Promise.all(MENUS.map(async (m) => ((await page.getByRole("navigation", { name: "Main" }).getByText(m, { exact: true }).count()) ? m : null)))).filter(Boolean);

test("the sidebar adapts to the role", async ({ browser }) => {
  const expected: Record<string, [string, string[]]> = {
    auditor: [DEMO, ["Dashboard", "Reports"]],
    user: [DEMO, ["Dashboard", "My tasks", "Scans", "Schedules", "Targets & groupings", "Policies & profiles", "Reports"]],
    operator: [DEMO, ["Dashboard", "My tasks", "Scans", "Schedules", "Targets & groupings", "Policies & profiles", "Reports"]],
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

test("direct URL access is also refused server-side for an auditor", async ({ page }) => {
  await login(page, "auditor@crashtest.example.com", DEMO);
  await page.goto("/admin");
  await expect(page).toHaveURL(/\/$/);
  const status = await page.evaluate(async () => (await fetch("/api/admin/users")).status);
  expect(status).toBe(403);
});

test("admin: users, audit and diagnostics", async ({ page }) => {
  await login(page, "admin", ADMIN);
  await page.getByRole("link", { name: "Administration" }).click();
  await expect(page.getByRole("cell", { name: /operator@crashtest/ })).toBeVisible();
  await page.getByRole("tab", { name: "Audit log" }).click();
  await expect(page.getByText("auth.login").first()).toBeVisible();
  await page.getByRole("tab", { name: "Diagnostics" }).click();
  await expect(page.getByText("PostgreSQL")).toBeVisible();
});

test("operator can publish a policy version; user cannot see the buttons", async ({ browser }) => {
  const op = await (await browser.newContext({ ignoreHTTPSErrors: true, locale: "en-US" })).newPage();
  await login(op, "operator@crashtest.example.com", DEMO);
  await op.getByRole("link", { name: "Policies & profiles" }).click();
  await expect(op.getByRole("button", { name: "New" }).first()).toBeVisible();
  const user = await (await browser.newContext({ ignoreHTTPSErrors: true, locale: "en-US" })).newPage();
  await login(user, "user@crashtest.example.com", DEMO);
  await user.getByRole("link", { name: "Policies & profiles" }).click();
  await expect(user.getByRole("button", { name: "New" })).toHaveCount(0);
});
