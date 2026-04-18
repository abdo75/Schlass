# Schlass — Vision and V1 Scope

---

## 1. Project Goal

A self-hosted, open-source identity provider targeted at EU-regulated SMEs — particularly in Luxembourg's financial sector (ManCos, fund administrators, boutique fintechs, law firms).

**The problem being solved:** Small regulated organisations need documented, auditable identity and access management to comply with DORA and NIS2. Okta and Entra ID are expensive, US-hosted, and over-engineered for their needs. Keycloak is free but notoriously painful to operate. There is no simple, EU-native, compliance-first IdP for this market.

**The positioning:** Not a feature-for-feature Okta replacement. A focused, self-hostable identity layer that is deployable in 30 minutes, compliance-first by default, and built specifically for EU-regulated SMEs.

**Key differentiators:**
- Self-hosted — customer owns their data, no US cloud dependency
- DORA/NIS2-ready audit logs out of the box, not as an afterthought
- Strong security defaults (MFA required, strong password policy) rather than permissive defaults
- Built for Luxembourg and EU market — data residency, GDPR-native
- Simple enough for a 30-person ManCo with no dedicated IT team

---

## 2. V1 Scope

### Deployment Model
Single binary, self-hosted, one organisation per instance. No multi-tenancy. No SaaS billing logic.

### Personas
| Persona | Description |
|---|---|
| Super Admin | Deploys and operates the instance. Configures clients, users, policies. |
| End User | Employee who authenticates through the IdP into company applications. |

Org Admin (non-technical helpdesk role) is deferred to v2.

### Protocol Layer
- OIDC / OAuth 2.1 compliant
- `/.well-known/openid-configuration` — discovery endpoint
- `/.well-known/jwks.json` — public key publication
- `/userinfo` — claims endpoint
- No SAML, no LDAP in v1

### Client Model
- Confidential and public client types
- Static registration only (Super Admin creates clients manually)
- Supported grant types: Authorization Code + PKCE (S256 only), Client Credentials, Refresh Token
- Implicit and ROPC never implemented
- No dynamic client registration
- No consent screen

### Scope Model
- System scopes only: `openid`, `profile`, `email`, `offline_access`
- Per-client allowed scope whitelist
- Standard OIDC claims mapping hardcoded
- `openid` + `profile` applied by default when no scope parameter sent
- Custom scopes deferred to v2

### Token Model
- Access Token: JWT, RS256, 15 minute default TTL
- ID Token: JWT, RS256, 15 minute default TTL
- Refresh Token: opaque, stored hashed in Valkey, 24 hour default TTL
- JWKS endpoint publishes minimum 2 keys at all times
- Manual key rotation in v1 (automatic rotation deferred to v2)
- Global TTL defaults only (per-client TTL overrides deferred to v2)

### Super Admin Features

**User Management**
- Create user (email, name, temporary password)
- Disable / re-enable user
- Delete user
- Reset user password
- Reset user MFA
- List and search users
- View user active sessions
- Force-terminate user sessions

**Client Management**
- Create client (type, name, redirect URIs, grant types, allowed scopes)
- Edit client settings
- Rotate client secret
- Enable / disable client
- Delete client
- List clients

**Scope Management**
- View system scopes (read-only)
- Configure default scopes

**Security & Instance Configuration**
- Global MFA policy — required by default
- Account lockout policy (threshold + duration)
- Password policy (min length, complexity) — strong defaults
- Signing key management (view active key, trigger rotation)
- Global token TTL defaults
- SMTP configuration

**Audit Log**
- Append-only, tamper-evident
- Structured fields: who (actor identity), what (event type), which resource, when (timezone-aware), from where (IP), outcome (success/failure)
- JSON export

### End User Features
- Login: email + password + optional TOTP challenge + redirect
- Forced password change on first login
- Self-service: change own password, enroll TOTP device
- Recovery: forgot password via email link
- MFA **disable**: self-service via password re-auth (`POST /api/me/mfa/disable`). Sessions revoked, next login re-enrolls.
- MFA **recovery** (user lost their authenticator): Super Admin only — user cannot prove possession.

### Security Primitives
- Rate limiting on all authentication endpoints
- Per-user `revoke_before` timestamp in Valkey — written on user disable, force-terminate, password change, password reset
- Session = refresh token (no separate sessions table)
- Append-only audit log enforced at database level via RLS

### First-Run
- Setup wizard on first deployment creates the first Super Admin
- `setup_complete` flag in `instance_config` — wizard returns 404 once complete

---

> **Note:** Database schema lives in `internal/database/migrations/` (authoritative). Sprint specs and execution plans live in `docs/superpowers/{specs,plans}/`. Current architectural conventions live in `CLAUDE.md`.
