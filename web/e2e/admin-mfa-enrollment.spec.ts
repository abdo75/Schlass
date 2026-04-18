// admin-mfa-enrollment.spec.ts
//
// Exercises the complete MFA flow in a real browser:
//   1. Admin signs in with password → redirected to /setup-mfa (forced enrollment)
//   2. Completes the 3-step wizard (scan QR, enter TOTP code, acknowledge codes)
//   3. Lands on /account (wizard always routes there after enrollment)
//   4. Signs out, signs back in → /mfa-challenge with TOTP code → /admin
//   5. Signs out, signs back in → uses a recovery code to pass the challenge
//   6. /account shows "9 recovery codes remaining" after burning one
//
// Sorting note: this file sorts between admin-role-routing.spec.ts and
// admin-user-management.spec.ts (a-m-i < a-r < a-u < l), so it runs before
// lockout.spec.ts which locks the shared admin.
//
// MFA isolation: the test body calls setMfaRequired(true) after the
// completedSetup fixture has run (which disables MFA). This ensures the
// ordering is: fixture sets up (disables MFA) → test body re-enables MFA →
// exercises enrollment/challenge → test body disables MFA again in finally.
// Using beforeEach/afterEach hooks here would cause ordering issues because
// Playwright initialises fixtures lazily (on first access in the test body),
// so beforeEach runs BEFORE fixture setup — a beforeEach setMfaRequired(true)
// would be overridden by the fixture's setMfaRequired(false) call.

import { generate } from "otplib";
import { test, expect, setMfaRequired } from "./fixtures";

const ADMIN_EMAIL = "e2e-admin@example.com";
const ADMIN_PASSWORD = "CorrectHorse42Battery";

test.describe("MFA enrollment and challenge", () => {
  // The full flow: enrollment wizard (scan + verify + codes) + TOTP challenge +
  // recovery-code challenge. Give it 90s to avoid flakiness under load.
  test.setTimeout(90000);

  test("full enrollment → TOTP challenge → recovery code login", async ({
    browser,
    completedSetup,
  }) => {
    // completedSetup has confirmed setup is done and called setMfaRequired(false).
    // Now re-enable MFA so subsequent logins trigger enrollment/challenge.
    void completedSetup;
    await setMfaRequired(true);

    // Use a fresh browser context — independent cookie jar from the fixture page.
    const context = await browser.newContext();
    const page = await context.newPage();

    try {
      // -------------------------------------------------------------------
      // Response listeners — capture the enrollment secret and recovery codes
      // from API responses without intercepting the request/response cycle.
      // Using page.on("response") instead of page.route() ensures the browser
      // processes Set-Cookie headers normally (route.fulfill strips cookies).
      // -------------------------------------------------------------------
      let capturedSecret = "";
      let capturedRecoveryCodes: string[] = [];

      page.on("response", async (response) => {
        const url = response.url();
        if (url.includes("/api/mfa/enrollment/start") && response.status() === 200) {
          try {
            const json = (await response.json()) as {
              secret_base32: string;
              provision_uri: string;
            };
            capturedSecret = json.secret_base32;
          } catch {
            // ignore parse errors
          }
        }
        if (url.includes("/api/mfa/enrollment/verify") && response.status() === 200) {
          try {
            const json = (await response.json()) as { recovery_codes: string[] };
            capturedRecoveryCodes = json.recovery_codes;
          } catch {
            // ignore parse errors
          }
        }
      });

      // -------------------------------------------------------------------
      // Step 1: Sign in → redirected to forced-enrollment /setup-mfa
      // -------------------------------------------------------------------
      await page.goto("/login");
      await page.getByLabel(/email/i).fill(ADMIN_EMAIL);
      await page.getByLabel(/password/i).fill(ADMIN_PASSWORD);
      await page.getByRole("button", { name: /sign in/i }).click();

      await page.waitForURL("**/setup-mfa", { timeout: 15000 });

      // -------------------------------------------------------------------
      // Step 2: Enrollment wizard — Step 1 (Scan)
      // Wait until the /start API resolves (the QR code renders), which means
      // capturedSecret is populated.
      // -------------------------------------------------------------------
      await expect
        .poll(() => capturedSecret, { timeout: 15000 })
        .not.toBe("");

      // The "Next" button is on Step 1.
      await page.getByRole("button", { name: /^next$/i }).click();

      // -------------------------------------------------------------------
      // Step 3: Enrollment wizard — Step 2 (Verify)
      // Compute the current TOTP code using the captured secret and fill
      // the six individual digit boxes.
      // -------------------------------------------------------------------
      const enrollCode = await generate({ secret: capturedSecret });
      const digitInputs = await page.getByLabel(/^Digit \d$/i).all();
      expect(digitInputs.length).toBe(6);
      for (let i = 0; i < 6; i++) {
        await digitInputs[i].fill(enrollCode[i]);
      }
      await page.getByRole("button", { name: /^verify$/i }).click();

      // -------------------------------------------------------------------
      // Step 4: Enrollment wizard — Step 3 (Recovery codes)
      // Wait until the verify response has been captured (recovery codes appear
      // in DOM) then check the ack checkbox and click "Finish setup".
      // -------------------------------------------------------------------
      await expect
        .poll(() => capturedRecoveryCodes.length, { timeout: 15000 })
        .toBe(10);

      // The acknowledgement is a plain <input type="checkbox">.
      await page.getByRole("checkbox").check();
      await page.getByRole("button", { name: /finish setup/i }).click();

      // super_admin lands at /admin (→ /admin/users) after enrollment.
      await page.waitForURL(/\/admin(\/|$)/, { timeout: 15000 });

      // Navigate to /account to verify enrolled state and sign out.
      await page.goto("/account");
      await page.waitForURL("**/account", { timeout: 5000 });
      // Verify enrolled state: the "Enabled" badge should be visible.
      await expect(page.getByText(/^Enabled$/i)).toBeVisible();

      // -------------------------------------------------------------------
      // Sign out via the SESSION card Sign out button on /account.
      // -------------------------------------------------------------------
      await page.getByRole("button", { name: /^sign out$/i }).click();
      await page.waitForURL("**/login", { timeout: 10000 });

      // -------------------------------------------------------------------
      // Second login: password correct → /mfa-challenge (TOTP mode)
      // -------------------------------------------------------------------
      await page.getByLabel(/email/i).fill(ADMIN_EMAIL);
      await page.getByLabel(/password/i).fill(ADMIN_PASSWORD);
      await page.getByRole("button", { name: /sign in/i }).click();
      await page.waitForURL("**/mfa-challenge", { timeout: 10000 });

      // No wait needed: enrollment complete sets last_used_totp_counter=0, so
      // the challenge accepts any code at step > 0 (i.e., any current TOTP code).
      // Replay prevention only fires when the same step is reused; since the
      // enrollment verify uses lastCounter=0 and doesn't advance the counter,
      // the challenge can use the same step as enrollment.
      const challengeCode = await generate({ secret: capturedSecret });
      const challengeInputs = await page.getByLabel(/^Digit \d$/i).all();
      expect(challengeInputs.length).toBe(6);
      for (let i = 0; i < 6; i++) {
        await challengeInputs[i].fill(challengeCode[i]);
      }
      await page.getByRole("button", { name: /^verify$/i }).click();

      // super_admin lands at /admin (which redirects to /admin/users)
      await page.waitForURL("**/admin/**", { timeout: 10000 });

      // -------------------------------------------------------------------
      // Third login: use a recovery code instead of TOTP
      // -------------------------------------------------------------------
      await page.goto("/account");
      await page.waitForURL("**/account", { timeout: 5000 });
      await page.getByRole("button", { name: /^sign out$/i }).click();
      await page.waitForURL("**/login", { timeout: 10000 });

      await page.getByLabel(/email/i).fill(ADMIN_EMAIL);
      await page.getByLabel(/password/i).fill(ADMIN_PASSWORD);
      await page.getByRole("button", { name: /sign in/i }).click();
      await page.waitForURL("**/mfa-challenge", { timeout: 10000 });

      // Toggle to recovery-code mode via the link.
      await page.getByRole("button", { name: /use a recovery code/i }).click();

      // Fill the recovery code input (placeholder="XXXX-XXXX").
      const recoveryInput = page.getByPlaceholder("XXXX-XXXX");
      await recoveryInput.fill(capturedRecoveryCodes[0]);
      await page.getByRole("button", { name: /^verify$/i }).click();

      await page.waitForURL("**/admin/**", { timeout: 10000 });

      // -------------------------------------------------------------------
      // Verify /account shows 9 of 10 recovery codes remaining.
      // -------------------------------------------------------------------
      await page.goto("/account");
      await page.waitForURL("**/account", { timeout: 5000 });
      // The account page renders "9 recovery codes remaining"
      await expect(page.getByText(/9 recovery codes remaining/i)).toBeVisible();
    } finally {
      await context.close();
      // Restore mfa_required=false so subsequent specs can sign in without MFA.
      await setMfaRequired(false);
    }
  });
});
