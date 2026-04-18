// Full OIDC authorization_code + PKCE flow against the dev-seeded client.
// Hits /authorize with an authenticated session, captures the 302 to the
// RP callback (its ?code + ?state), and exchanges them at /token for
// access + id + refresh tokens. Also exercises /userinfo and the
// refresh-token grant's rotate-on-every-use discipline.
//
// File sorts AFTER lockout.spec.ts (l < o), which locks the shared admin
// for 15 minutes. Each test in this file runs clearAdminLockout() first
// to reset locked_until and failed_login_attempts — cheap and explicit,
// avoids renaming files or refactoring shared-admin ownership.

import { test, expect, setMfaRequired } from "./fixtures";
import { Client } from "pg";
import {
  E2E_CLIENT_SECRET,
  E2E_REDIRECT_URI,
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

test.describe("OIDC authorization_code + PKCE flow", () => {
  test.setTimeout(60000);

  test("admin → /authorize → /oidc/dev-callback with code → /token exchange", async ({
    browser,
    completedSetup,
  }) => {
    void completedSetup;
    await setMfaRequired(false);
    await clearAdminLockout();

    const clientID = await getDevClientID();
    const { verifier, challenge } = generatePKCE();
    const state = randomState();

    const context = await browser.newContext();
    const page = await context.newPage();
    try {
      // Log in to the admin SPA session.
      await page.goto("/login");
      await page.getByLabel(/email/i).fill(ADMIN_EMAIL);
      await page.getByLabel(/password/i).fill(ADMIN_PASSWORD);
      await page.getByRole("button", { name: /sign in/i }).click();
      await page.waitForURL(/\/(admin|account)/, { timeout: 15000 });

      // Hit /authorize. The backend validates params, mints a code, and
      // 302s to the RP callback. The dev-callback path has no SPA route,
      // so the SPA falls through to the index page — but the URL carries
      // the ?code= and ?state= we need, and Playwright captures it.
      const authorizeURL = buildAuthorizeURL({ clientID, state, challenge });
      await page.goto(authorizeURL);
      await page.waitForURL(
        (url) =>
          url.pathname === "/oidc/dev-callback" && url.searchParams.has("code"),
        { timeout: 15000 },
      );

      const url = new URL(page.url());
      const code = url.searchParams.get("code");
      const returnedState = url.searchParams.get("state");
      expect(code, "code query param missing").toBeTruthy();
      expect(returnedState).toBe(state);

      // Exchange the code at /token. Playwright's request context does not
      // share the browser's cookies, which is correct here — /token is
      // called by the RP backend, not the browser.
      const tokenRes = await page.request.post("/token", {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        data: new URLSearchParams({
          grant_type: "authorization_code",
          code: code!,
          redirect_uri: E2E_REDIRECT_URI,
          client_id: clientID,
          client_secret: E2E_CLIENT_SECRET,
          code_verifier: verifier,
        }).toString(),
      });
      expect(tokenRes.status(), await tokenRes.text()).toBe(200);
      const tokens = (await tokenRes.json()) as {
        access_token: string;
        id_token: string;
        refresh_token: string;
        token_type: string;
        expires_in: number;
      };
      expect(tokens.token_type).toBe("Bearer");
      expect(tokens.access_token).toBeTruthy();
      expect(tokens.id_token).toBeTruthy();
      expect(tokens.refresh_token).toBeTruthy();

      // /userinfo with the access token returns the user's claims.
      const userInfoRes = await page.request.get("/userinfo", {
        headers: { Authorization: `Bearer ${tokens.access_token}` },
      });
      expect(userInfoRes.status()).toBe(200);
      const claims = (await userInfoRes.json()) as { email: string };
      expect(claims.email).toBe(ADMIN_EMAIL);

      // Refresh-token grant rotates the refresh_token per OAuth 2.1.
      const refreshRes = await page.request.post("/token", {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        data: new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: tokens.refresh_token,
          client_id: clientID,
          client_secret: E2E_CLIENT_SECRET,
        }).toString(),
      });
      expect(refreshRes.status(), await refreshRes.text()).toBe(200);
      const refreshed = (await refreshRes.json()) as {
        access_token: string;
        refresh_token: string;
      };
      expect(refreshed.refresh_token).not.toBe(tokens.refresh_token);
    } finally {
      await context.close();
    }
  });
});
