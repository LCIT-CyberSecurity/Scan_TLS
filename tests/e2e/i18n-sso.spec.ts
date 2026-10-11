import { expect, test } from "@playwright/test";
import { DEMO, login } from "./helpers";

test("language: browser detection, manual choice persisted and prioritised", async ({ browser }) => {
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true, locale: "de-DE" });
  const page = await ctx.newPage();
  await page.goto("/");
  await expect(page.getByRole("button", { name: "Anmelden", exact: true })).toBeVisible(); // German detected
  await page.getByRole("button", { name: "FR" }).click();
  await expect(page.getByRole("button", { name: "Se connecter", exact: true })).toBeVisible();
  await page.getByLabel(/identifiant/i).fill("user2@crashtest.example.com");
  await page.getByLabel(/^mot de passe$/i).fill(DEMO);
  await page.getByRole("button", { name: "Se connecter", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Tableau de bord" })).toBeVisible();
  // saved on the profile: a fresh German-language browser context signing in as the same user gets French
  await page.locator(".user-menu summary").click(); // account menu (details/summary, as in LCIT-Sign)
  await page.getByRole("menuitem", { name: "Préférences" }).click();
  await page.getByLabel("Langue").selectOption("fr");
  await page.reload();
  await expect(page.getByRole("heading", { name: "Préférences" })).toBeVisible();
  const other = await (await browser.newContext({ ignoreHTTPSErrors: true, locale: "de-DE" })).newPage();
  await other.goto("/");
  await other.getByLabel(/username|identifiant|benutzername/i).fill("user2@crashtest.example.com");
  await other.getByLabel(/^(password|mot de passe|passwort)$/i).fill(DEMO);
  await other.getByRole("button", { name: /^(sign in|se connecter|anmelden)$/i }).click();
  await expect(other.getByRole("heading", { name: "Tableau de bord" })).toBeVisible();
  // leave the demo user as found (language back to "follow the browser")
  await other.evaluate(async () => { const me = await (await fetch("/api/auth/me")).json(); await fetch("/api/auth/preferences", { method: "PATCH", headers: { "Content-Type": "application/json", "X-CSRF-Token": me.csrf_token }, body: JSON.stringify({ locale: "" }) }); });
});

test("SSO (mock provider): sign in provisions a USER", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Sign in with SSO" }).click();
  await expect(page.getByRole("navigation", { name: "Main" })).toBeVisible({ timeout: 30_000 });
  await page.locator(".user-menu summary").click();
  await expect(page.locator(".user-menu summary").getByText("USER")).toBeVisible(); // the role is shown under the name
});
