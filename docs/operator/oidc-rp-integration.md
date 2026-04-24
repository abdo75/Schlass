# Integrating a third-party OIDC relying party

A walkthrough for wiring [Grafana OSS](https://grafana.com/) as a relying party. Same pattern works for any generic-OAuth RP (Gitea, Nextcloud, custom apps).

## Prerequisites

- Running Schlass instance (`make dev` or a real deploy).
- Logged in as `super_admin` with a TOTP authenticator enrolled.
- Docker + docker compose.
- `/admin/clients` reachable from your browser.

## 1. Register the RP as a client

1. Open `/admin/clients/new` in the Schlass admin UI.
2. Fill in:
   - **Name**: `Grafana`
   - **Type**: `confidential`
   - **Redirect URIs**: `http://localhost:3001/login/generic_oauth`
   - **Scopes**: `openid`, `profile`, `email`
   - **Grants**: `authorization_code`, `refresh_token`
3. Submit. The modal shows the client ID + generated secret **once** — copy both. Lost secrets require a rotation.

## 2. Bring up Grafana

Create a local `docker-compose.yml` (do not commit it):

```yaml
services:
  grafana:
    image: grafana/grafana-oss:11.5.0
    ports:
      - "3001:3000"
    extra_hosts:
      - "host.docker.internal:host-gateway"
    environment:
      GF_SERVER_ROOT_URL: http://localhost:3001/

      GF_AUTH_GENERIC_OAUTH_ENABLED: "true"
      GF_AUTH_GENERIC_OAUTH_NAME: Schlass
      GF_AUTH_GENERIC_OAUTH_CLIENT_ID: <paste-client-id>
      GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET: <paste-client-secret>
      GF_AUTH_GENERIC_OAUTH_SCOPES: openid profile email

      # Browser hits Schlass directly at localhost:3000.
      GF_AUTH_GENERIC_OAUTH_AUTH_URL: http://localhost:3000/authorize
      # Grafana's server-side calls Schlass via the host bridge.
      GF_AUTH_GENERIC_OAUTH_TOKEN_URL: http://host.docker.internal:3000/token
      GF_AUTH_GENERIC_OAUTH_API_URL: http://host.docker.internal:3000/userinfo

      GF_AUTH_GENERIC_OAUTH_LOGIN_ATTRIBUTE_PATH: preferred_username
      GF_AUTH_GENERIC_OAUTH_EMAIL_ATTRIBUTE_PATH: email
      # Schlass does not emit a `name` claim; Grafana falls back to LOGIN
      # for display. Set NAME_ATTRIBUTE_PATH only if you later add a real
      # name claim in internal/oidc/claims.go.

      GF_AUTH_GENERIC_OAUTH_AUTO_LOGIN: "false"
      GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_STRICT: "false"
      GF_AUTH_GENERIC_OAUTH_ALLOW_SIGN_UP: "true"

      # OAuth 2.1 — Schlass rejects non-PKCE /authorize with invalid_request.
      # Grafana supports PKCE but it is off by default.
      GF_AUTH_GENERIC_OAUTH_USE_PKCE: "true"
```

Launch:

```bash
docker compose up -d
```

## 3. Sign in

- Open `http://localhost:3001`.
- Click **Sign in with Schlass** at the bottom of the Grafana login form.
- Schlass handles the full auth dance: password → TOTP challenge → consent-less redirect back to Grafana.
- First-time sign-in provisions a Grafana user (Viewer role) and lands on the home dashboard with the identity shown top-right.

Stop the RP:

```bash
docker compose down
```

## Gotchas

- **PKCE is mandatory.** Without `GF_AUTH_GENERIC_OAUTH_USE_PKCE=true` the RP sends a non-PKCE `/authorize` and Schlass returns `invalid_request`. OAuth 2.1, not negotiable.
- **Browser-visible URL vs server-to-server URL.** The browser reaches Schlass at `localhost:3000`; Grafana's backend (inside Docker) must reach the same host via `host.docker.internal:3000`. Mixing them up yields `invalid_grant` or `connection refused` at the token endpoint.
- **Client secret rotation.** After `/admin/clients/<id>` rotate-secret, the old secret works for 24h overlap then stops. Update the RP's env + restart before the overlap expires.
- **Role attribute.** Schlass does not emit a `role` claim. Either leave `GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_STRICT=false` (Grafana assigns Viewer) or map roles on the Grafana side.
- **Claims emitted.** `openid` → `sub`; `profile` → `preferred_username` (= email), `updated_at`; `email` → `email`, `email_verified`. No `name`. See `internal/oidc/claims.go`.

## Forensics

Every successful or failed exchange writes an audit row:

```sql
SELECT
  created_at, event_type, outcome,
  actor_email,
  target_id AS client_id,
  metadata
FROM audit_logs
WHERE event_type LIKE 'oidc.%'
ORDER BY created_at DESC
LIMIT 20;
```

Expected shape for a clean login: `oidc.code.exchanged` (`success`) follows the user's `login.succeeded` + `mfa.challenge_succeeded`. For failures, see the `oidc.code.<reason>` family (`client_mismatch`, `redirect_mismatch`, `pkce_mismatch`, `user_not_found`, `grant_removed`, `scope_removed`, `user_disabled`) and `oidc.refresh.reuse_detected`.
