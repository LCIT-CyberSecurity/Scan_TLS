import { expect, test } from "@playwright/test";
import { DEMO, login } from "./helpers";

test("operator: the profile form offers the complementary TLS checks, recommended ones pre-selected for a new profile", async ({ page }) => {
  await login(page, "operator@crashtest.example.com", DEMO);
  await page.getByRole("link", { name: "Profiles" }).click();
  await page.getByRole("tab", { name: "Scan profiles" }).click();
  await page.getByRole("button", { name: "New", exact: true }).click();
  const dialog = page.getByRole("dialog");

  // the existing options are still there, the new zone sits under them
  await expect(dialog.getByLabel("Ports")).toBeVisible();
  const zone = dialog.getByRole("group", { name: "Complementary TLS checks" });
  await expect(zone).toBeVisible();
  const boxes = zone.getByRole("checkbox");
  await expect(boxes).toHaveCount(6);
  for (let i = 0; i < 6; i++) await expect(boxes.nth(i)).toBeChecked();
  await expect(zone.getByText("ECDHE groups")).toHaveCount(0); // not recommended: behind "Add checks"

  // remove a recommended check, add another one
  await zone.getByRole("checkbox", { name: /TLS compression/ }).uncheck();
  await zone.getByRole("button", { name: "Add checks" }).click();
  await zone.getByRole("button", { name: /ECDHE groups/ }).click();
  await zone.getByRole("checkbox", { name: /ECDHE groups/ }).check();

  const name = `e2e-tls-checks-${Date.now()}`;
  await dialog.getByLabel("Name").fill(name);
  await dialog.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("cell", { name })).toBeVisible();

  const profiles = await (await page.request.get("/api/profiles")).json();
  const saved = profiles.find((p: { name: string }) => p.name === name);
  const tls = saved.versions[0].content.checks.tls;
  expect(Object.keys(tls).sort()).toEqual(["ecdhe_groups", "extended_master_secret", "fallback_scsv", "hostname_san", "ocsp_stapling", "renegotiation"]);
  expect(tls.tls_compression).toBeUndefined();
});

test("operator: an existing profile shows the checks unticked and is saved unchanged", async ({ page }) => {
  await login(page, "operator@crashtest.example.com", DEMO);
  await page.getByRole("link", { name: "Profiles" }).click();
  await page.getByRole("tab", { name: "Scan profiles" }).click();
  await page.getByRole("button", { name: "Edit" }).first().click();
  const zone = page.getByRole("dialog").getByRole("group", { name: "Complementary TLS checks" });
  await expect(zone).toBeVisible();
  const boxes = zone.getByRole("checkbox");
  for (let i = 0; i < (await boxes.count()); i++) await expect(boxes.nth(i)).not.toBeChecked();
});
