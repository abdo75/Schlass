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

    // Post-redesign: /admin redirects to /admin/users. The AdminLayout renders
    // a sidebar (<aside>) + a <main> pane with AdminPageHeader showing "Users"
    // as a plain <div> (not an <h1>).
    await page.waitForURL("**/admin/users", { timeout: 15000 });
    // Verify the page title inside the main pane (scoped away from the nav).
    await expect(
      page.locator("main").getByText("Users", { exact: true }).first(),
    ).toBeVisible();
    // The admin email appears on the UserMenuPopover pill button in the header.
    await expect(
      page.getByRole("button", { name: uniqueEmail }),
    ).toBeVisible();

    // Sign out is inside the UserMenuPopover. Click the admin pill (its
    // aria-label is the email) to open the popover, then click "Sign out".
    await page.getByRole("button", { name: uniqueEmail }).click();
    await page.getByRole("button", { name: /sign out/i }).click();
    await expect(page).toHaveURL(/\/login$/);

    // Verify the session is actually destroyed server-side: /admin must
    // bounce back to /login instead of rendering the admin area.
    await page.goto("/admin");
    await expect(page).toHaveURL(/\/login$/);
  });
});
