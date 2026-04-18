import { test as base, expect, type Page } from "@playwright/test";
import { Client } from "pg";

export { expect };

// ---------------------------------------------------------------------------
// MFA policy helper — allows the MFA spec to re-enable MFA while keeping all
// other specs unaffected (MFA is orthogonal to what they test).
// Connects to the Postgres instance exposed by docker-compose on localhost:5432.
// ---------------------------------------------------------------------------
export async function setMfaRequired(value: boolean): Promise<void> {
  const client = new Client({
    host: "localhost",
    port: 5432,
    database: "schlass",
    user: "postgres",
    password: "postgres",
  });
  await client.connect();
  try {
    // The Go config store JSON-unmarshals the value column, so it must be
    // the JSON literal "true" or "false" (not the SQL string 'true'/'false').
    // JSONB columns accept bare unquoted booleans as valid JSON.
    const result = await client.query(
      "UPDATE instance_config SET value = $1::jsonb WHERE key = 'mfa_required'",
      [value ? "true" : "false"],
    );
    if (result.rowCount === 0) {
      throw new Error(`setMfaRequired: key 'mfa_required' not found in instance_config`);
    }
  } finally {
    await client.end();
  }
}

// Test ordering note: Playwright runs files in alphabetical order, and with
// `fullyParallel: false` + `workers: 1` the order within a file is also
// deterministic. `lockout.spec.ts` leaves the shared admin account locked
// for the remainder of the CI run (default lockout is 15 minutes), so every
// spec that needs a working login MUST sort before `lockout.spec.ts`.
// Current order:
//   admin-user-management.spec.ts  (logs in — must precede lockout)
//   auth.spec.ts                    (logs in — must precede lockout)
//   disabled-user.spec.ts           (logs in — must precede lockout)
//   lockout.spec.ts                 (locks the admin)
//   preferences.spec.ts             (does NOT log in — safe after lockout)
// Note: `user-management` would sort after `lockout` (u > l), which is why
// the file is named `admin-user-management.spec.ts` instead. Do not rename
// files without re-checking this order.

type Fixtures = {
  uniqueEmail: string;
  adminPassword: string;
  completedSetup: Page;
  adminPage: Page;
  newUserEmail: string;
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
    // Disable MFA so every spec using completedSetup can sign in without the
    // TOTP enrollment redirect. The default is mfa_required=true (migration
    // seed). The MFA spec does NOT use completedSetup — it manages mfa_required
    // in its own test body after setup is confirmed complete.
    await setMfaRequired(false);
    await use(page);
  },
  // adminPage extends completedSetup by performing the shared-admin login
  // and lands the page at /admin/users (the default admin landing after T16
  // turned /admin into a redirect).
  adminPage: async ({ page, completedSetup, uniqueEmail, adminPassword }, use) => {
    void completedSetup;
    await page.getByLabel(/email/i).fill(uniqueEmail);
    await page.getByLabel(/password/i).fill(adminPassword);
    await page.getByRole("button", { name: /sign in/i }).click();
    await page.waitForURL("**/admin/users", { timeout: 15000 });
    await use(page);
  },
  // newUserEmail produces a unique, deterministic-ish email per test. We
  // include testInfo.title so multiple tests in the same run get distinct
  // emails, and Date.now() so reruns within the same run don't collide.
  newUserEmail: async ({}, use, testInfo) => {
    const slug = testInfo.title
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, "")
      .slice(0, 40);
    await use(`e2e-user-${Date.now()}-${slug}@example.com`);
  },
});
