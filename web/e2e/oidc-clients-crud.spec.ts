// Full admin journey for OIDC client management:
// Create → reveal modal → detail → edit name → rotate secret →
// disable → enable → delete (type-to-confirm).
//
// File sorts AFTER lockout.spec.ts (o > l), so each test calls
// clearAdminLockout() first — same pattern as oidc-code-flow.spec.ts.

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

test.describe("OIDC clients CRUD — full admin journey", () => {
  test.setTimeout(90000);

  test("create → reveal modal → detail → edit name → rotate secret → disable → enable → delete", async ({
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
      // 2. Navigate to /admin/clients — should show list page
      // ------------------------------------------------------------------
      await page.goto("/admin/clients");
      await page.waitForURL("**/admin/clients", { timeout: 10000 });
      // The page title is "Clients" (from t("clients.title"))
      await expect(page.getByRole("link", { name: /new client/i })).toBeVisible({ timeout: 10000 });

      // ------------------------------------------------------------------
      // 3. Click "+ New client" → fill form
      // ------------------------------------------------------------------
      await page.getByRole("link", { name: /new client/i }).click();
      await page.waitForURL("**/admin/clients/new", { timeout: 10000 });

      // Fill the client name
      await page.getByLabel(/^name$/i).fill("e2e-test-client");

      // Fill the first redirect URI (there is one empty input by default)
      const redirectInputs = page.locator('input[placeholder="https://..."]');
      await redirectInputs.first().fill("https://rp.e2e.example.com/cb");

      // Leave default scopes and grants checked (all selected by default)

      // ------------------------------------------------------------------
      // 4. Click Create → secret modal appears
      // ------------------------------------------------------------------
      await page.getByRole("button", { name: /^create$/i }).click();

      // ClientSecretModal: wait for "Client secret" heading
      const modal = page.locator(".fixed").filter({
        has: page.locator("text=Client secret"),
      });
      await modal.waitFor({ state: "visible", timeout: 15000 });

      // Assert client_id and client_secret fields are present (both rendered
      // as <code> elements inside the modal)
      const codeElements = modal.locator("code");
      await expect(codeElements).toHaveCount(2);

      // Capture the client_id from the first code element (Client ID)
      const clientId = (await codeElements.first().textContent()) ?? "";
      expect(clientId.length).toBeGreaterThan(0);

      // ------------------------------------------------------------------
      // 5. Click Done → routes to /admin/clients/:id detail page
      // ------------------------------------------------------------------
      await modal.getByRole("button", { name: /done/i }).click();
      await page.waitForURL(/\/admin\/clients\/[0-9a-f-]+$/i, {
        timeout: 15000,
      });

      // ------------------------------------------------------------------
      // 6. Assert header shows the client name + Active badge
      // ------------------------------------------------------------------
      await expect(page.getByRole("heading", { name: "e2e-test-client" })).toBeVisible();
      // StatusBadge renders the status text; the detail page header strip has
      // the name as an h1 and the badge right beside it.
      await expect(page.getByText(/^Active$/i).first()).toBeVisible();

      // ------------------------------------------------------------------
      // 7. Click Edit on the Identity section → change name → Save
      // ------------------------------------------------------------------
      // The Identity section has an "Edit" link/button
      await page.getByRole("button", { name: /^edit$/i }).first().click();

      // Clear the name input and type new name
      const nameInput = page.locator("#client-name-edit");
      await nameInput.clear();
      await nameInput.fill("e2e-renamed");

      await page.getByRole("button", { name: /^save$/i }).click();

      // After save, the heading should reflect the new name
      await expect(page.getByRole("heading", { name: "e2e-renamed" })).toBeVisible({ timeout: 10000 });

      // ------------------------------------------------------------------
      // 8. Click Rotate secret → confirm dialog → secret modal opens
      // ------------------------------------------------------------------
      page.once("dialog", (dialog) => void dialog.accept());
      await page.getByRole("button", { name: /rotate secret/i }).click();

      // ClientSecretModal should appear again
      const rotateModal = page.locator(".fixed").filter({
        has: page.locator("text=Client secret"),
      });
      await rotateModal.waitFor({ state: "visible", timeout: 15000 });

      // Done closes the modal
      await rotateModal.getByRole("button", { name: /done/i }).click();
      await expect(rotateModal).not.toBeVisible({ timeout: 5000 });

      // ------------------------------------------------------------------
      // 9. Click Disable → confirm → assert Disabled badge
      // ------------------------------------------------------------------
      page.once("dialog", (dialog) => void dialog.accept());
      // The danger zone has a "Disable" button (not "Disable client" — that's
      // the section heading text, the button label is just "Disable")
      await page.getByRole("button", { name: /^disable$/i }).click();

      // Wait for the page to re-load and show the Disabled badge
      await expect(page.getByText(/^Disabled$/i).first()).toBeVisible({ timeout: 10000 });

      // ------------------------------------------------------------------
      // 10. Click Enable → confirm → assert Active badge returns
      // ------------------------------------------------------------------
      page.once("dialog", (dialog) => void dialog.accept());
      await page.getByRole("button", { name: /^enable$/i }).click();

      await expect(page.getByText(/^Active$/i).first()).toBeVisible({ timeout: 10000 });

      // ------------------------------------------------------------------
      // 11. Click Delete → type-to-confirm modal → type name → Delete permanently
      // ------------------------------------------------------------------
      await page.getByRole("button", { name: /^delete$/i }).click();

      // DeleteConfirmModal appears
      const deleteModal = page.locator(".fixed").filter({
        has: page.locator("text=Delete permanently"),
      });
      await deleteModal.waitFor({ state: "visible", timeout: 10000 });

      // Type the client name to enable the Delete button
      await deleteModal.locator('input[type="text"]').fill("e2e-renamed");

      await deleteModal.getByRole("button", { name: /delete permanently/i }).click();

      // Should navigate back to /admin/clients
      await page.waitForURL("**/admin/clients", { timeout: 15000 });

      // The deleted client should no longer appear in the list
      await expect(page.getByText("e2e-renamed")).not.toBeVisible();
    } finally {
      await context.close();
    }
  });
});
