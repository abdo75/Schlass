import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false, // setup wizard is global state; don't race
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1, // same reason — single-worker to keep setup deterministic
  reporter: [
    ["html", { open: "never" }],
    ["list"],
  ],
  use: {
    baseURL: "http://localhost:3000",
    trace: "on-first-retry",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  // DO NOT use Playwright's built-in webServer — the dev stack runs via
  // docker compose, not `npm run dev`. CI and local both use `make e2e`
  // which starts docker compose first, waits for health, then invokes
  // `npx playwright test`.
});
