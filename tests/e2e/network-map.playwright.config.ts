import { defineConfig, devices } from "@playwright/test";

const desktop = devices["Desktop Chrome"];

export default defineConfig({
  testDir: ".",
  testMatch: "network-map.spec.ts",
  timeout: 300_000,
  workers: 1,
  reporter: [["list"]],
  outputDir: "./results/network-map",
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "https://localhost:15200",
    ignoreHTTPSErrors: true,
    locale: "en-US",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [
    { name: "Chromium", use: { ...desktop } },
    { name: "Google Chrome", use: { ...desktop, channel: "chrome" } },
  ],
});
