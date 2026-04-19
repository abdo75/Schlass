// Signing keys rotate button + success banner.
// File sorts AFTER lockout.spec.ts (s > l), so clearAdminLockout() is
// called first — same pattern as oidc-code-flow.spec.ts.

import { test, expect, setMfaRequired } from "./fixtures";
import { Client } from "pg";

const ADMIN_EMAIL = "e2e-admin@example.com";
const ADMIN_PASSWORD = "CorrectHorse42Battery";

async function clearAdminLockout(): Promise<void> {
  const client = new Client({
    host: "localhost",
    port: 5432,
    database: "schlass",
    user: "postgres",
    password: "postgres",
  });
  await client.connect();
  try {
    await client.query(
      `UPDATE users SET locked_until = NULL, failed_login_attempts = 0 WHERE email = $1`,
      [ADMIN_EMAIL],
    );
  } finally {
    await client.end();
  }
}

test.describe("signing keys — rotate", () => {
  test.setTimeout(60000);

  test("rotate button triggers confirm dialog and shows success banner", async ({
    browser,
    completedSetup,
  }) => {
    void completedSetup;
    await setMfaRequired(false);
    await clearAdminLockout();

    const context = await browser.newContext();
    const page = await context.newPage();

    try {
      // ------------------------------------------------------------------
      // 1. Log in as admin
      // ------------------------------------------------------------------
      await page.goto("/login");
      await page.getByLabel(/email/i).fill(ADMIN_EMAIL);
      await page.getByLabel(/password/i).fill(ADMIN_PASSWORD);
      await page.getByRole("button", { name: /sign in/i }).click();
      await page.waitForURL(/\/(admin|account)/, { timeout: 15000 });

      // ------------------------------------------------------------------
      // 2. Navigate to /admin/signing-keys
      // ------------------------------------------------------------------
      await page.goto("/admin/signing-keys");
      await page.waitForURL("**/admin/signing-keys", { timeout: 10000 });

      // ------------------------------------------------------------------
      // 3. Assert the page renders with "Rotate key" button + "How rotation works"
      // ------------------------------------------------------------------
      await expect(
        page.getByRole("button", { name: /rotate key/i }),
      ).toBeVisible({ timeout: 10000 });

      // The explainer heading is rendered as uppercase text in a <div>
      await expect(page.getByText(/how rotation works/i)).toBeVisible();

      // ------------------------------------------------------------------
      // 4. Accept the window.confirm dialog, then click Rotate key
      // ------------------------------------------------------------------
      page.once("dialog", (dialog) => void dialog.accept());
      await page.getByRole("button", { name: /rotate key/i }).click();

      // ------------------------------------------------------------------
      // 5. Assert the success banner appears
      // ------------------------------------------------------------------
      // The success banner text includes "Signing key rotated"
      await expect(
        page.getByText(/signing key rotated/i),
      ).toBeVisible({ timeout: 15000 });
    } finally {
      await context.close();
    }
  });
});
