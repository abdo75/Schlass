import { test, expect } from "./fixtures";

// Named `admin-user-management` rather than `user-management` so it sorts
// before `lockout.spec.ts` alphabetically — see fixtures.ts for the rule.

test.describe("user management", () => {
  test("admin creates a user, who then logs in and is forced to change password", async ({
    browser,
    adminPage,
    newUserEmail,
  }) => {
    const tempPassword = "TempPassw0rdForE2E";
    const finalPassword = "FinalPassw0rdForE2E";

    // Admin creates the user via the UI.
    await adminPage.getByRole("button", { name: /create user/i }).click();
    await adminPage.waitForURL("**/admin/users/new", { timeout: 10000 });

    await adminPage.getByLabel(/email/i).fill(newUserEmail);
    await adminPage.getByLabel(/temporary password/i).fill(tempPassword);
    // Role defaults to "user"; leave it as-is.
    await adminPage
      .getByRole("button", { name: /^create user$/i })
      .click();

    // Landed on the user detail page for the new user.
    await adminPage.waitForURL(/\/admin\/users\/[0-9a-f-]+$/i, {
      timeout: 10000,
    });
    await expect(
      adminPage.getByRole("heading", { name: newUserEmail, level: 1 }),
    ).toBeVisible();

    // Navigate back to the list and confirm the row is visible. Use a regex
    // URL match anchored to the end of the path — Playwright's `**` glob
    // matches arbitrary trailing segments, so "**/admin/users" would resolve
    // immediately while still on /admin/users/:id.
    await adminPage.getByRole("button", { name: /back to users/i }).click();
    await adminPage.waitForURL(/\/admin\/users$/, { timeout: 10000 });
    await expect(
      adminPage.getByRole("cell", { name: newUserEmail }),
    ).toBeVisible();

    // Second browser context for the new user — independent cookie jar.
    const userContext = await browser.newContext();
    const userPage = await userContext.newPage();
    try {
      await userPage.goto("/login");
      await userPage.getByLabel(/email/i).fill(newUserEmail);
      await userPage.getByLabel(/password/i).fill(tempPassword);
      await userPage.getByRole("button", { name: /sign in/i }).click();

      // force_password_change=true bounces the user to /change-password.
      await userPage.waitForURL("**/change-password", { timeout: 15000 });

      await userPage.getByLabel(/current password/i).fill(tempPassword);
      await userPage.getByLabel(/^new password$/i).fill(finalPassword);
      await userPage
        .getByLabel(/confirm new password/i)
        .fill(finalPassword);
      await userPage
        .getByRole("button", { name: /^change password$/i })
        .click();

      // After clearing the flag the ChangePasswordPage navigates to /admin
      // which redirects to /admin/users.
      await userPage.waitForURL("**/admin/users", { timeout: 15000 });
      await expect(
        userPage.getByRole("heading", { name: /users/i, level: 1 }),
      ).toBeVisible();
    } finally {
      await userContext.close();
    }
  });

  test("admin cannot disable their own account", async ({
    adminPage,
    uniqueEmail,
  }) => {
    // Find self in the list and click the row to open the detail page.
    // Scope by role="cell" so we don't click the sidebar email div, which
    // is not a navigable target.
    await adminPage.goto("/admin/users");
    await adminPage.getByRole("cell", { name: uniqueEmail }).click();

    await adminPage.waitForURL(/\/admin\/users\/[0-9a-f-]+$/i, {
      timeout: 10000,
    });
    await expect(
      adminPage.getByRole("heading", { name: uniqueEmail, level: 1 }),
    ).toBeVisible();

    // Click Disable user, then confirm inside the AlertDialog. Scope the
    // confirm button to the dialog so it doesn't match the page-level
    // Disable button.
    await adminPage.getByRole("button", { name: /disable user/i }).click();
    const dialog = adminPage.getByRole("alertdialog");
    await expect(dialog).toBeVisible();
    await dialog.getByRole("button", { name: /^disable$/i }).click();

    // Backend rejects with CANNOT_OPERATE_ON_SELF → translated banner.
    await expect(adminPage.getByRole("alert")).toContainText(
      /cannot perform this action on your own account/i,
    );

    // Force a fresh list fetch so we're asserting against server state, not a
    // stale DOM snapshot, then scope the Active check to the admin's own row.
    await adminPage.goto("/admin/users");
    const adminRow = adminPage.getByRole("row", {
      name: new RegExp(uniqueEmail.replace(/[.+]/g, "\\$&")),
    });
    await expect(adminRow).toBeVisible();
    await expect(adminRow).toContainText(/active/i);
  });
});
