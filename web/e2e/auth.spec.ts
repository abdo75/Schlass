import { test, expect } from "./fixtures";

test.describe("authentication", () => {
  test("can complete setup, log in, reach the admin area, and log out", async ({
    page,
    uniqueEmail,
    adminPassword,
    completedSetup,
  }) => {
    // Fixture has already completed setup (or skipped the wizard) and landed
    // at /login.
    void completedSetup;
    await expect(page).toHaveURL(/\/login$/);

    await page.getByLabel(/email/i).fill(uniqueEmail);
    await page.getByLabel(/password/i).fill(adminPassword);
    await page.getByRole("button", { name: /sign in/i }).click();

    // Post-T16: /admin is a redirect to /admin/users. The old DashboardPage
    // with its "Welcome, <email>" greeting is gone — AdminLayout renders a
    // sidebar with the admin's email in a footer block and the Users page
    // heading in the main pane.
    await page.waitForURL("**/admin/users", { timeout: 15000 });
    await expect(
      page.getByRole("heading", { name: /users/i, level: 1 }),
    ).toBeVisible();
    // The sidebar (aside / role=complementary) shows the signed-in admin's
    // email in its footer block. The UsersPage table ALSO renders the
    // admin's row containing the same email, so scope to the sidebar to
    // keep the locator strict-mode-safe.
    await expect(
      page.getByRole("complementary").getByText(uniqueEmail),
    ).toBeVisible();

    await page.getByRole("button", { name: /sign out/i }).click();
    await expect(page).toHaveURL(/\/login$/);

    // Verify the session is actually destroyed server-side: /admin must
    // bounce back to /login instead of rendering the admin area.
    await page.goto("/admin");
    await expect(page).toHaveURL(/\/login$/);
  });
});
