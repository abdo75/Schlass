import { test, expect } from "./fixtures";

test.describe("theme toggle", () => {
  test("cycles light, dark, system and persists the explicit choice", async ({
    page,
    completedSetup,
  }) => {
    void completedSetup;

    // Force a clean theme state before the first navigation so previous
    // tests can't bleed in a persisted value.
    await page.goto("/login");
    await page.evaluate(() => localStorage.removeItem("schlass-theme"));
    await page.reload();

    // The ThemeToggle cycles: light → dark → system → light.
    // See web/src/components/ThemeToggle.tsx.
    const html = page.locator("html");
    const toggle = page.getByRole("button", { name: /toggle theme/i });

    // Fresh localStorage → "system". Headless Chromium defaults to light,
    // so `.dark` should be absent.
    await expect(html).not.toHaveClass(/dark/);

    // Click once → explicit "light". Still no .dark class.
    await toggle.click();
    await expect(html).not.toHaveClass(/dark/);

    // Click again → explicit "dark".
    await toggle.click();
    await expect(html).toHaveClass(/dark/);

    // Click again → "system". Headless default is light, so .dark removed.
    await toggle.click();
    await expect(html).not.toHaveClass(/dark/);

    // Click again → back to explicit "light".
    await toggle.click();
    await expect(html).not.toHaveClass(/dark/);

    // Persistence: set explicit dark, reload, expect dark to stick.
    await toggle.click(); // light → dark
    await expect(html).toHaveClass(/dark/);
    await page.reload();
    await expect(page.locator("html")).toHaveClass(/dark/);
  });

  // Regression guard for the Sprint 2 bug fixed in commit 2fad326:
  // ThemeToggle in "system" mode did not subscribe to matchMedia change
  // events, so flipping the OS preference didn't update the html class.
  test("system mode reacts to prefers-color-scheme changes", async ({
    page,
    completedSetup,
  }) => {
    void completedSetup;

    await page.goto("/login");
    await page.evaluate(() => localStorage.removeItem("schlass-theme"));
    await page.reload();

    const html = page.locator("html");

    // Force OS preference to light.
    await page.emulateMedia({ colorScheme: "light" });
    await expect(html).not.toHaveClass(/dark/);

    // Force OS preference to dark — html must gain the .dark class without
    // any user interaction (this is the part that used to be broken).
    await page.emulateMedia({ colorScheme: "dark" });
    await expect(html).toHaveClass(/dark/);

    // And back to light.
    await page.emulateMedia({ colorScheme: "light" });
    await expect(html).not.toHaveClass(/dark/);
  });
});

test.describe("language switcher", () => {
  test("changes form labels across EN, FR, DE", async ({
    page,
    completedSetup,
  }) => {
    void completedSetup;
    await page.goto("/login");

    // LanguageSwitcher renders three small buttons labelled EN / FR / DE
    // in the top-left corner. See web/src/components/LanguageSwitcher.tsx.
    const en = page.getByRole("button", { name: /^EN$/ });
    const fr = page.getByRole("button", { name: /^FR$/ });
    const de = page.getByRole("button", { name: /^DE$/ });

    // English → default
    await expect(
      page.getByRole("button", { name: /sign in/i }),
    ).toBeVisible();

    // French
    await fr.click();
    await expect(
      page.getByRole("button", { name: /se connecter/i }),
    ).toBeVisible();

    // German
    await de.click();
    await expect(
      page.getByRole("button", { name: /^anmelden$/i }),
    ).toBeVisible();

    // Back to English
    await en.click();
    await expect(
      page.getByRole("button", { name: /sign in/i }),
    ).toBeVisible();
  });
});
