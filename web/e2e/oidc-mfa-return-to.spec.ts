// return_to survives the TOTP challenge in a real browser. Scenario:
//
//   1. Admin is enrolled in MFA (seeded inline via /api/mfa/enrollment/*).
//   2. Anonymous browser visits /authorize → backend sees no session →
//      302 /login?return_to=<encoded /authorize URL>.
//   3. LoginPage reads ?return_to=, threads it into /api/login body.
//   4. Backend bounces to /mfa-challenge (return_to stashed in
//      mfa:challenge:<token> Valkey hash).
//   5. Challenge succeeds → 200 JSON with redirect_to = original /authorize.
//   6. SPA follows redirect_to, /authorize mints a code, 302s to RP callback.

import { generate } from "otplib";
import { test, expect, setMfaRequired } from "./fixtures";
import { Client } from "pg";
import {
  buildAuthorizeURL,
  generatePKCE,
  getDevClientID,
  randomState,
} from "./oidc-helpers";

const ADMIN_EMAIL = "e2e-admin@example.com";
const ADMIN_PASSWORD = "CorrectHorse42Battery";

async function clearAdminLockout(): Promise<void> {
  const client = new Client({
    host: "localhost",
    port: 5432,
    database: "schlass",
    user: "postgres",
    password: "postgres",
  });
  await client.connect();
  try {
    await client.query(
      `UPDATE users SET locked_until = NULL, failed_login_attempts = 0 WHERE email = $1`,
      [ADMIN_EMAIL],
    );
  } finally {
    await client.end();
  }
}

test.describe("return_to survives MFA challenge", () => {
  test.setTimeout(90000);

  test("anon /authorize → /login → /mfa-challenge → /authorize → RP callback", async ({
    browser,
    completedSetup,
  }) => {
    void completedSetup;
    await clearAdminLockout();
    await setMfaRequired(true);

    // --- Enroll the admin if not already enrolled. --------------------
    const context = await browser.newContext();
    const page = await context.newPage();

    let capturedSecret = "";
    page.on("response", async (response) => {
      const url = response.url();
      if (url.includes("/api/mfa/enrollment/start") && response.status() === 200) {
        try {
          const json = (await response.json()) as { secret_base32: string };
          capturedSecret = json.secret_base32;
        } catch {
          /* ignore */
        }
      }
    });

    try {
      await page.goto("/login");
      await page.getByLabel(/email/i).fill(ADMIN_EMAIL);
      await page.getByLabel(/password/i).fill(ADMIN_PASSWORD);
      await page.getByRole("button", { name: /sign in/i }).click();

      // Either the first-login forced-enrollment path OR direct challenge
      // if a prior spec left the admin enrolled.
      await Promise.race([
        page.waitForURL("**/setup-mfa", { timeout: 15000 }),
        page.waitForURL("**/mfa-challenge", { timeout: 15000 }),
        page.waitForURL(/\/(admin|account)/, { timeout: 15000 }),
      ]);

      if (page.url().includes("/setup-mfa")) {
        await expect.poll(() => capturedSecret, { timeout: 15000 }).not.toBe("");
        await page.getByRole("button", { name: /^next$/i }).click();
        const enrollCode = await generate({ secret: capturedSecret });
        const digitInputs = await page.getByLabel(/^Digit \d$/i).all();
        for (let i = 0; i < 6; i++) {
          await digitInputs[i].fill(enrollCode[i]);
        }
        await page.getByRole("button", { name: /^verify$/i }).click();
        await page.getByRole("checkbox").check();
        await page.getByRole("button", { name: /finish setup/i }).click();
        await page.waitForURL(/\/(admin|account)/, { timeout: 15000 });
      }

      // Sign out to start the deep-link flow from an anonymous state.
      await page.goto("/account");
      await page.getByRole("button", { name: /^sign out$/i }).click();
      await page.waitForURL("**/login", { timeout: 10000 });
    } catch (err) {
      await context.close();
      throw err;
    }

    // --- Anon visits /authorize → /login?return_to=... ------------------
    try {
      const clientID = await getDevClientID();
      const { challenge } = generatePKCE();
      const state = randomState();
      const authorizeURL = buildAuthorizeURL({ clientID, state, challenge });

      // We need a fresh context so no session cookie leaks through — the
      // sign-out above already cleared it, but a brand-new context is
      // the hygienic choice.
      await context.close();
      const anonContext = await browser.newContext();
      const anonPage = await anonContext.newPage();

      try {
        await anonPage.goto(authorizeURL);
        await anonPage.waitForURL(
          (url) =>
            url.pathname === "/login" && url.searchParams.has("return_to"),
          { timeout: 10000 },
        );

        // Fill password → /mfa-challenge.
        await anonPage.getByLabel(/email/i).fill(ADMIN_EMAIL);
        await anonPage.getByLabel(/password/i).fill(ADMIN_PASSWORD);
        await anonPage.getByRole("button", { name: /sign in/i }).click();
        await anonPage.waitForURL("**/mfa-challenge", { timeout: 10000 });

        // Submit TOTP — the SPA reads redirect_to from the response and
        // follows it via window.location.href.
        const challengeCode = await generate({ secret: capturedSecret });
        const challengeInputs = await anonPage.getByLabel(/^Digit \d$/i).all();
        for (let i = 0; i < 6; i++) {
          await challengeInputs[i].fill(challengeCode[i]);
        }
        await anonPage.getByRole("button", { name: /^verify$/i }).click();

        // Final landing: /oidc/dev-callback with ?code= proves the full
        // round-trip survived the MFA stop.
        await anonPage.waitForURL(
          (url) =>
            url.pathname === "/oidc/dev-callback" &&
            url.searchParams.has("code") &&
            url.searchParams.get("state") === state,
          { timeout: 15000 },
        );
      } finally {
        await anonContext.close();
      }
    } finally {
      await setMfaRequired(false);
    }
  });
});
