import { test, expect } from "./fixtures";

// Un-defers the Sprint 2 "disabled user is force-logged-out" case. This
// requires admin user-management endpoints (Sprint 3) which didn't exist
// when the test was first written.

test.describe("disabled user revocation", () => {
  test("disabling a user kills their active session on next navigation", async ({
    browser,
    adminPage,
    newUserEmail,
  }) => {
    const tempPassword = "DisableMeLater42";

    // Admin creates user B via the UI.
    await adminPage.getByRole("button", { name: /create user/i }).click();
    await adminPage.waitForURL("**/admin/users/new", { timeout: 10000 });
    await adminPage.getByLabel(/email/i).fill(newUserEmail);
    await adminPage.getByLabel(/temporary password/i).fill(tempPassword);
    await adminPage.getByRole("button", { name: /^create user$/i }).click();
    await adminPage.waitForURL(/\/admin\/users\/[0-9a-f-]+$/i, {
      timeout: 10000,
    });
    // Capture the user's detail-page URL so the admin can come back to it.
    const userDetailUrl = adminPage.url();

    // User B logs in from a separate context.
    const userContext = await browser.newContext();
    const userPage = await userContext.newPage();
    try {
      await userPage.goto("/login");
      await userPage.getByLabel(/email/i).fill(newUserEmail);
      await userPage.getByLabel(/password/i).fill(tempPassword);
      await userPage.getByRole("button", { name: /sign in/i }).click();
      // force_password_change bounces them to /change-password.
      await userPage.waitForURL("**/change-password", { timeout: 15000 });

      // Admin now disables user B via the detail page.
      await adminPage.goto(userDetailUrl);
      await expect(
        adminPage.getByRole("heading", { name: newUserEmail, level: 1 }),
      ).toBeVisible();
      await adminPage.getByRole("button", { name: /disable user/i }).click();
      const dialog = adminPage.getByRole("alertdialog");
      await expect(dialog).toBeVisible();
      await dialog.getByRole("button", { name: /^disable$/i }).click();
      // Detail page should now show Disabled status — wait for the state
      // change before testing the other context to avoid a race.
      await expect(
        adminPage.getByText(/^disabled$/i).first(),
      ).toBeVisible({ timeout: 10000 });

      // User B navigates to a guarded route — forcing a fresh request through
      // the auth middleware, which sees the disabled user, deletes the Valkey
      // session, and AuthGuard bounces to /login. A client-side reload() of
      // /change-password could be served from the SPA shell without hitting a
      // guarded endpoint, so use goto("/admin") for a deterministic check.
      await userPage.goto("/admin");
      await expect(userPage).toHaveURL(/\/login/, { timeout: 15000 });
    } finally {
      await userContext.close();
    }
  });
});
