import { test, expect } from "./fixtures";

test.describe("Audit log viewer", () => {
  test("admin sees timeline, filters by view + actor, opens side panel, exports CSV", async ({ adminPage, page }) => {
    await adminPage.goto("/admin/audit");

    await expect(page.getByTestId("audit-page").getByText("Audit log")).toBeVisible();
    await expect(page.getByTestId("audit-tab-all")).toHaveAttribute("aria-selected", "true");

    await page.getByTestId("audit-tab-sign-in").click();
    await expect(page).toHaveURL(/view=sign-in/);

    await page.getByRole("button", { name: "+ Actor" }).click();
    await page.getByPlaceholder(/Search actors/i).fill("admin");
    await page.getByRole("option", { name: /admin@|e2e-admin@/ }).click();
    await expect(page).toHaveURL(/actor=.*admin/);

    const firstRow = page.getByTestId("audit-event-row").first();
    await firstRow.click();
    const panel = page.getByRole("dialog", { name: /Event detail/i });
    await expect(panel).toBeVisible();
    await expect(panel.getByText(/signed in|opened the audit log|authorized/)).toBeVisible();

    await panel.getByRole("link", { name: /admin@|e2e-admin@/ }).click();
    await expect(panel).toBeHidden();
    await expect(page.getByText(/Actor: .*admin@/)).toBeVisible();

    const downloadPromise = page.waitForEvent("download");
    await page.getByRole("button", { name: "Export" }).click();
    await page.getByRole("menuitem", { name: "CSV" }).click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/audit-log\.csv/);
  });
});
