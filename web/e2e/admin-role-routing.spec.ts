import { test, expect } from "./fixtures";

test.describe("role-based routing", () => {
  test("non-admin lands on /account and cannot reach /admin", async ({
    browser,
    adminPage,
    newUserEmail,
  }) => {
    // Admin creates a role=user through the UI.
    await adminPage.getByRole("link", { name: /create user/i }).click();
    await adminPage.waitForURL("**/admin/users/new", { timeout: 10000 });
    await adminPage.getByLabel(/email/i).fill(newUserEmail);
    // The role defaults to "user" in the create form — no need to change it.
    await adminPage.getByRole("button", { name: /^create user$/i }).click();

    // Capture the server-generated temp password from the reveal modal.
    const modal = adminPage.locator(".fixed").filter({ has: adminPage.locator("code") });
    await modal.waitFor({ state: "visible", timeout: 10000 });
    const tempPassword = (await modal.locator("code").textContent()) ?? "";
    expect(tempPassword.length).toBeGreaterThan(0);
    await modal.getByRole("button", { name: /done/i }).click();

    // New user signs in from a fresh browser context (so cookies don't
    // leak across the admin session and the user session).
    const userContext = await browser.newContext();
    const userPage = await userContext.newPage();
    try {
      await userPage.goto("/login");
      await userPage.getByLabel(/email/i).fill(newUserEmail);
      await userPage.getByLabel(/password/i).fill(tempPassword);
      await userPage.getByRole("button", { name: /sign in/i }).click();

      // force_password_change=true bounces them to /change-password.
      await userPage.waitForURL("**/change-password", { timeout: 15000 });
      const newPassword = "NewUserPass1Battery";
      await userPage.getByLabel(/current password/i).fill(tempPassword);
      await userPage.getByLabel(/^new password$/i).fill(newPassword);
      await userPage.getByLabel(/confirm new password/i).fill(newPassword);
      // The submit button in forced mode uses the "Confirm" translation key.
      await userPage.getByRole("button", { name: /^confirm$/i }).click();

      // ChangePasswordForm navigates role-aware: role=user lands on /account.
      await userPage.waitForURL("**/account", { timeout: 15000 });
      // The /account page shows the user's email as the identity hero heading.
      await expect(userPage.getByRole("heading", { name: newUserEmail })).toBeVisible();

      // Typing /admin directly must redirect back to /account via AdminGuard.
      await userPage.goto("/admin/users");
      await userPage.waitForURL("**/account", { timeout: 10000 });
      await expect(userPage.getByRole("heading", { name: newUserEmail })).toBeVisible();

      // Sign out returns to /login so the new user's cookie is cleaned up.
      await userPage.getByRole("button", { name: /sign out/i }).click();
      await userPage.waitForURL("**/login", { timeout: 10000 });
    } finally {
      await userContext.close();
    }
  });
});
