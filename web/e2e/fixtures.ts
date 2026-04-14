import { test as base, expect, type Page } from "@playwright/test";

export { expect };

// Test ordering note: Playwright runs files in the order it discovers them,
// and with `fullyParallel: false` + `workers: 1` the order within a file is
// also deterministic. `lockout.spec.ts` leaves the admin account locked for
// the remainder of the CI run, so it must run AFTER any test that needs a
// working login. Alphabetical file ordering gives us:
//   auth.spec.ts → lockout.spec.ts → preferences.spec.ts
// `preferences.spec.ts` does not log in (it only exercises the theme toggle
// and the language switcher on /login), so the locked account is harmless
// there. Do not rename files without re-checking this order.

type Fixtures = {
  uniqueEmail: string;
  adminPassword: string;
  completedSetup: Page;
};

// The first test that sees a fresh stack completes the setup wizard and
// creates the shared admin. Subsequent tests in the same run skip the wizard
// (which returns 404 once setup is complete) and reuse that admin.
const SHARED_ADMIN_EMAIL = "e2e-admin@example.com";
const SHARED_ADMIN_PASSWORD = "CorrectHorse42Battery";

export const test = base.extend<Fixtures>({
  uniqueEmail: async ({}, use) => {
    // All tests share a single admin — the setup wizard can only run once
    // per fresh database, so we cannot create a new admin per test.
    // `make e2e` and the CI job both start from `docker compose down -v`
    // which guarantees a clean database at the start of each run.
    await use(SHARED_ADMIN_EMAIL);
  },
  adminPassword: async ({}, use) => {
    await use(SHARED_ADMIN_PASSWORD);
  },
  completedSetup: async ({ page, uniqueEmail, adminPassword }, use) => {
    // Is setup still available? Ask the API directly — 200 means the wizard
    // is expected, 404 means setup already happened. This avoids racing with
    // the SPA's own bootstrap redirect. In the SPA, the /login route is
    // wrapped in a Bootstrap guard that redirects to /setup when setup is
    // incomplete, so we cannot probe setup state via the SPA without first
    // completing (or skipping) the wizard.
    const setupStatus = await page.request.get("/api/setup");
    const wizardNeeded = setupStatus.status() === 200;

    if (wizardNeeded) {
      await page.goto("/setup");
      // Wait until the Complete Setup button is mounted.
      await page
        .getByRole("button", { name: /complete setup/i })
        .waitFor({ state: "visible", timeout: 15000 });

      await page.locator("#instance-name").fill("E2E Test Instance");
      await page.locator("#email").fill(uniqueEmail);
      await page.locator("#password").fill(adminPassword);
      await page.locator("#confirm-password").fill(adminPassword);
      await page.getByRole("button", { name: /complete setup/i }).click();
      await page.waitForURL("**/login", { timeout: 15000 });
    } else {
      await page.goto("/login");
      await page.waitForURL("**/login", { timeout: 15000 });
    }
    await use(page);
  },
});
