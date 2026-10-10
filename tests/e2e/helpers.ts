import { expect, type Page } from "@playwright/test";

export const DEMO = "CrashTest-Demo-2026!"; // CrashTest only (see tests/crashtest/seed.py)
export const ADMIN = "CrashTest-Admin-2026!";

export async function login(page: Page, username: string, password: string) {
  await page.goto("/");
  await page.getByLabel(/username|identifiant|benutzername/i).fill(username);
  await page.getByLabel(/^(password|mot de passe|passwort)$/i).fill(password);
  await page.getByRole("button", { name: /^(sign in|se connecter|anmelden)$/i }).click();
  await expect(page.getByRole("navigation", { name: "Main" })).toBeVisible(); // the login page has its own h1
}
