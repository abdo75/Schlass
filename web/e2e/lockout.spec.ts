import { test, expect } from "./fixtures";

// NOTE: this spec locks the shared admin account for the remainder of the
// run (default lockout_duration_secs is 15 minutes). It must run AFTER any
// test that needs a working login. Alphabetical file ordering gives:
//   auth.spec.ts → lockout.spec.ts → preferences.spec.ts
// `preferences.spec.ts` does not log in, so the lock is harmless there.
// If you add a new spec that needs login, name it so it sorts before
// `lockout`.

test.describe("account lockout", () => {
  test("five wrong passwords in a row lock the account", async ({
    page,
    uniqueEmail,
    adminPassword,
    completedSetup,
  }) => {
    void completedSetup;
    await page.goto("/login");

    // Five wrong attempts in a row.
    for (let i = 0; i < 5; i++) {
      await page.getByLabel(/email/i).fill(uniqueEmail);
      await page.getByLabel(/password/i).fill("not-the-right-password");
      await page.getByRole("button", { name: /sign in/i }).click();
      // Each failure: still on /login with an error visible.
      await expect(page).toHaveURL(/\/login$/);
      await expect(page.getByRole("alert")).toBeVisible();
    }

    // Sixth attempt with the CORRECT password — must still be rejected
    // because the account is now locked.
    await page.getByLabel(/password/i).fill(adminPassword);
    await page.getByRole("button", { name: /sign in/i }).click();

    // The error message must indicate a locked account. Matches the
    // translated string in any of the three supported locales.
    await expect(page.getByRole("alert")).toContainText(
      /locked|verrouillé|gesperrt/i,
    );

    // Still on /login, not /admin.
    await expect(page).toHaveURL(/\/login$/);
  });
});
