// Shared helpers for the OIDC E2E specs (M8). Three responsibilities:
//
//   1. Pull the dev-seeded client_id out of Postgres. The seed row is
//      idempotent across container restarts, so its UUID is the only piece
//      of state we cannot hard-code.
//   2. Expose the deterministic client_secret set by docker-compose.e2e.yml
//      (SCHLASS_DEV_SECRET) so specs can sign /token requests without
//      scraping container logs.
//   3. Compute PKCE verifier + S256 challenge pairs.

import { createHash, randomBytes } from "crypto";
import { Client } from "pg";

// Matches SCHLASS_DEV_SECRET in docker-compose.e2e.yml. Updating one
// without the other produces 401 invalid_client at /token.
export const E2E_CLIENT_SECRET = "e2e-deterministic-secret-do-not-ship";

// The dev-seed helper always registers exactly one redirect URI.
export const E2E_REDIRECT_URI = "http://localhost:3000/oidc/dev-callback";

export async function getDevClientID(): Promise<string> {
  const client = new Client({
    host: "localhost",
    port: 5432,
    database: "schlass",
    user: "postgres",
    password: "postgres",
  });
  await client.connect();
  try {
    const res = await client.query<{ id: string }>(
      `SELECT id FROM clients WHERE name = 'dev-test-client' LIMIT 1`,
    );
    if (res.rowCount === 0) {
      throw new Error(
        "dev-test-client not seeded — ensure SCHLASS_DEV=1 is set in the E2E stack",
      );
    }
    return res.rows[0].id;
  } finally {
    await client.end();
  }
}

export interface PKCEPair {
  verifier: string;
  challenge: string;
}

export function generatePKCE(): PKCEPair {
  // RFC 7636: code_verifier = 43–128 URL-safe chars; code_challenge is
  // base64url(SHA256(verifier)). 32 random bytes → 43-char verifier.
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

export function randomState(): string {
  return randomBytes(16).toString("base64url");
}

export function buildAuthorizeURL(args: {
  clientID: string;
  state: string;
  challenge: string;
  scope?: string;
  nonce?: string;
}): string {
  const params = new URLSearchParams({
    response_type: "code",
    client_id: args.clientID,
    redirect_uri: E2E_REDIRECT_URI,
    scope: args.scope ?? "openid profile email offline_access",
    state: args.state,
    code_challenge: args.challenge,
    code_challenge_method: "S256",
  });
  if (args.nonce) params.set("nonce", args.nonce);
  return "/authorize?" + params.toString();
}
