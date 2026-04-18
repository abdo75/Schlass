// /oidc/error local-error page: when /authorize rejects an untrusted
// trigger (unknown client_id, unregistered redirect_uri), the backend 302s
// to /oidc/error?ref=... and the SPA renders a friendly page with the ref
// echoed for correlation.

import { test, expect } from "./fixtures";
import { Client } from "pg";
import { getDevClientID, generatePKCE, randomState } from "./oidc-helpers";

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
      `UPDATE users SET locked_until = NULL, failed_login_attempts = 0 WHERE email = 'e2e-admin@example.com'`,
    );
  } finally {
    await client.end();
  }
}

test.describe("/oidc/error local-error page", () => {
  test.setTimeout(30000);

  test("unregistered redirect_uri renders /oidc/error with ref", async ({
    browser,
    completedSetup,
  }) => {
    void completedSetup;
    await clearAdminLockout();

    const clientID = await getDevClientID();
    const { challenge } = generatePKCE();
    const state = randomState();

    const context = await browser.newContext();
    const page = await context.newPage();
    try {
      // Hostile redirect_uri (not in the client's registered list). /authorize
      // refuses to bounce back to an unknown RP and renders locally instead.
      const params = new URLSearchParams({
        response_type: "code",
        client_id: clientID,
        redirect_uri: "https://evil.example.com/callback",
        scope: "openid",
        state,
        code_challenge: challenge,
        code_challenge_method: "S256",
      });
      await page.goto("/authorize?" + params.toString());

      await page.waitForURL(
        (url) => url.pathname === "/oidc/error" && url.searchParams.has("ref"),
        { timeout: 10000 },
      );

      // The SPA error page shows a stable reference ID so operators can
      // cross-reference logs. The exact i18n string is not asserted — the
      // ref prefix "err_" is part of the backend correlation format.
      const ref = new URL(page.url()).searchParams.get("ref")!;
      expect(ref).toMatch(/^err_/);
    } finally {
      await context.close();
    }
  });

  test("missing client_id renders /oidc/error", async ({
    browser,
    completedSetup,
  }) => {
    void completedSetup;
    await clearAdminLockout();

    const context = await browser.newContext();
    const page = await context.newPage();
    try {
      await page.goto("/authorize?response_type=code&redirect_uri=x");
      await page.waitForURL(
        (url) => url.pathname === "/oidc/error" && url.searchParams.has("ref"),
        { timeout: 10000 },
      );
    } finally {
      await context.close();
    }
  });
});
