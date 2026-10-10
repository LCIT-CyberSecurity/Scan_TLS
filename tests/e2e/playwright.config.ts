import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: ".",
  testMatch: "*.spec.ts",
  timeout: 240_000,
  workers: 1,
  reporter: [["list"]],
  use: { baseURL: process.env.E2E_BASE_URL ?? "https://localhost:5100", ignoreHTTPSErrors: true, locale: "en-US", trace: "retain-on-failure", screenshot: "only-on-failure" },
  outputDir: "./results",
});
