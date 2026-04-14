import { test, expect } from "./fixtures";

test.describe("authentication", () => {
  test("can complete setup, log in, see the dashboard, and log out", async ({
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

    await expect(page).toHaveURL(/\/admin$/);
    await expect(page.getByText(/welcome/i)).toBeVisible();
    await expect(page.getByText(uniqueEmail)).toBeVisible();

    await page.getByRole("button", { name: /sign out/i }).click();
    await expect(page).toHaveURL(/\/login$/);

    // Verify the session is actually destroyed server-side: /admin must
    // bounce back to /login instead of rendering the dashboard.
    await page.goto("/admin");
    await expect(page).toHaveURL(/\/login$/);
  });
});
