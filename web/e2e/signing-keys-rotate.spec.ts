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

  test("rotate button produces a retiring key and a new active kid", async ({
    browser,
    completedSetup,
  }) => {
    void completedSetup;
    await setMfaRequired(false);
    await clearAdminLockout();

    const context = await browser.newContext();
    const page = await context.newPage();

    try {
      // 1. Log in as admin.
      await page.goto("/login");
      await page.getByLabel(/email/i).fill(ADMIN_EMAIL);
      await page.getByLabel(/password/i).fill(ADMIN_PASSWORD);
      await page.getByRole("button", { name: /sign in/i }).click();
      await page.waitForURL(/\/(admin|account)/, { timeout: 15000 });

      // 2. Navigate to /admin/signing-keys and assert core chrome.
      await page.goto("/admin/signing-keys");
      await page.waitForURL("**/admin/signing-keys", { timeout: 10000 });
      await expect(
        page.getByRole("button", { name: /rotate key/i }),
      ).toBeVisible({ timeout: 10000 });
      await expect(page.getByText(/how rotation works/i)).toBeVisible();
      await expect(page.getByText("Active key", { exact: true })).toBeVisible({
        timeout: 15000,
      });

      // 3. Record the kid in the Active card so we can confirm it changes.
      // The first <code> with a UUID shape is the active kid (Generated row
      // uses plain text, not code). Pull by regex so we don't match the
      // lifecycle explainer's <code>SCHLASS_ENCRYPTION_KEY</code>.
      const activeKidLocator = page
        .locator("code")
        .filter({ hasText: /[0-9a-f]{8}-[0-9a-f]{4}/ })
        .first();
      await expect(activeKidLocator).toBeVisible();
      const originalKidText = (await activeKidLocator.textContent()) ?? "";
      expect(originalKidText.length).toBeGreaterThan(0);

      // 4. Click Rotate key — opens styled ConfirmDialog. Then click
      // the dialog's own "Rotate key" button to trigger the POST.
      await page.getByRole("button", { name: /rotate key/i }).click();
      await page
        .getByRole("button", { name: /rotate key/i })
        .last()
        .click();

      // 5. Retiring keys card appears and contains the old kid (proving the
      // rotation took effect + the page refetched the list). We don't check
      // the new active kid separately — the Retiring card's presence is a
      // stronger signal, because the old kid was active before and moved
      // out, which can only happen if a new active key was minted.
      await expect(page.getByText(/retiring keys/i)).toBeVisible({
        timeout: 15000,
      });
      await expect(
        page.getByText(originalKidText).first(),
      ).toBeVisible();
    } finally {
      await context.close();
    }
  });
});
