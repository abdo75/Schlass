import { test, expect } from "./fixtures";

// Named `admin-user-management` rather than `user-management` so it sorts
// before `lockout.spec.ts` alphabetically — see fixtures.ts for the rule.

test.describe("user management", () => {
  test("admin creates a user, who then logs in and is forced to change password", async ({
    browser,
    adminPage,
    newUserEmail,
  }) => {
    const finalPassword = "FinalPassw0rdForE2E";

    // Admin creates the user via the UI. "Create user" is a <Link> (rendered
    // as <a>) styled as a button — match by role="link".
    await adminPage.getByRole("link", { name: /create user/i }).click();
    await adminPage.waitForURL("**/admin/users/new", { timeout: 10000 });

    await adminPage.getByLabel(/email/i).fill(newUserEmail);
    // Role defaults to "user"; leave it as-is. No password field — the
    // server generates a temporary password.
    await adminPage
      .getByRole("button", { name: /^create user$/i })
      .click();

    // The TempPasswordModal opens showing the server-generated password.
    // It is a fixed overlay <div> without role="dialog", so locate by the
    // <code> element inside it.
    const modal = adminPage.locator(".fixed").filter({ has: adminPage.locator("code") });
    await modal.waitFor({ state: "visible", timeout: 10000 });
    const tempPassword = (await modal.locator("code").textContent()) ?? "";
    expect(tempPassword.length).toBeGreaterThan(0);

    // Click Done to dismiss the modal — navigates to the user detail page.
    await modal.getByRole("button", { name: /done/i }).click();

    // Landed on the user detail page for the new user.
    await adminPage.waitForURL(/\/admin\/users\/[0-9a-f-]+$/i, {
      timeout: 10000,
    });
    // AdminPageHeader renders the email as a plain <div>, not an <h1>.
    await expect(adminPage.getByText(newUserEmail).first()).toBeVisible();

    // Navigate back to the list via the breadcrumb link (scope to <main> to
    // avoid matching the sidebar nav link which also says "Users").
    await adminPage.locator("main").getByRole("link", { name: /users/i }).first().click();
    await adminPage.waitForURL(/\/admin\/users$/, { timeout: 10000 });
    // The UsersPage uses a CSS Grid layout (not <table>), so there are no
    // role="cell" elements. The email is inside a <Link> row — match by text.
    await expect(adminPage.getByText(newUserEmail).first()).toBeVisible();

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
      // The submit button label is now "Confirm" (was "Change password").
      await userPage
        .getByRole("button", { name: /^confirm$/i })
        .click();

      // After clearing the flag the ChangePasswordForm navigates role-aware:
      // role=user lands on /account (AdminGuard blocks /admin for non-admins).
      await userPage.waitForURL("**/account", { timeout: 15000 });
      // The /account page shows the user's email as the identity hero heading.
      await expect(userPage.getByRole("heading", { name: newUserEmail })).toBeVisible();
    } finally {
      await userContext.close();
    }
  });

  test("admin cannot disable their own account", async ({
    adminPage,
    uniqueEmail,
  }) => {
    // Navigate to the users list and click the admin's row to open detail.
    // The UsersPage renders rows as <Link> elements (role="link") using a
    // CSS Grid — no role="cell". The email also appears in the
    // UserMenuPopover pill, so scope to <a> links to match only the row.
    await adminPage.goto("/admin/users");
    await adminPage.waitForURL(/\/admin\/users$/, { timeout: 10000 });
    await adminPage.locator("a").filter({ hasText: uniqueEmail }).click();

    await adminPage.waitForURL(/\/admin\/users\/[0-9a-f-]+$/i, {
      timeout: 10000,
    });
    // AdminPageHeader title is a plain <div>, not an <h1>.
    await expect(adminPage.getByText(uniqueEmail).first()).toBeVisible();

    // The detail page for "self" shows a SelfActions card without disable
    // or delete buttons — the UI prevents self-ops. Verify the Disable
    // button is not present.
    await expect(
      adminPage.getByRole("button", { name: /disable user/i }),
    ).toHaveCount(0);

    // Confirm the admin stays active — navigate back to the list and check.
    await adminPage.goto("/admin/users");
    await adminPage.waitForURL(/\/admin\/users$/, { timeout: 10000 });
    // The row containing the admin's email should show "Active" status.
    const adminRow = adminPage.locator("a").filter({ hasText: uniqueEmail });
    await expect(adminRow).toBeVisible();
    await expect(adminRow).toContainText(/active/i);
  });
});
