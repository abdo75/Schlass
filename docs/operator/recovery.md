# Operator — password recovery for super_admin accounts

Super_admin accounts **cannot** reset their password via the email flow at `/forgot-password`. This is a deliberate compliance control: ENISA NIS2 (Jun-2025) requires phishing-resistant MFA for privileged accounts, and TOTP + email-delivered reset links are both phishable in real-time.

The sanctioned recovery paths, in order of preference:

1. **Ask another super_admin** to reset via `/admin/users/:id/reset-password`. This is the everyday path.
2. **If no other super_admin exists**, use the CLI below.

## CLI recovery

### Prerequisites

- Shell access to a host that can reach the Schlass Postgres + Valkey.
- The Schlass binary (same version as production).
- `SCHLASS_ENCRYPTION_KEY` + `SCHLASS_DATABASE_URL` + `SCHLASS_PUBLIC_URL` in the environment — the CLI reuses the server's config loader.

### Usage

```bash
SCHLASS_RECOVERY_MODE=1 ./schlass recovery-reset --email admin@example.com
```

Output is a single line:

```
Reset URL: https://auth.example.com/reset-password/<token>
```

The URL is valid for **1 hour** and single-use. Deliver it out-of-band (Signal, call, etc.) to the locked-out admin.

### What it does

- Looks up the user by lowercased email.
- Refuses if the user is not found.
- Refuses if the user's role is not `super_admin` (prevents misuse for non-admin resets).
- Mints a 32-byte `crypto/rand` token, HMAC-hashes it, writes the row with a 1-hour TTL.
- Writes one audit row: `event_type = password_reset.recovery_issued`, `actor_email = system:recovery`, metadata includes `{token_id, target_email, invoker: {hostname, os_user}}`.
- Commits, prints the URL, exits.

### What it does NOT do

- Does NOT require an SMTP connection (no email sent).
- Does NOT start the HTTP server.
- Does NOT log the plaintext token anywhere except the one stdout line (capture it from shell history manually if needed; avoid piping to files with lax permissions).

## Best practice

- **Deploy with ≥ 2 super_admins from day one.** Single-admin instances should document their backup access plan before going to production.
- **Review audit logs on every recovery run.** Filter: `SELECT * FROM audit_logs WHERE event_type = 'password_reset.recovery_issued'`.
- **Rotate the CLI-issued password on first login.** The issued token sets `force_password_change = false` (same as self-reset), so the user owns the password choice — follow up with a policy nudge.
- **Treat `SCHLASS_RECOVERY_MODE=1` like `sudo`.** Anyone with shell access + the env flag can mint admin recovery tokens. Keep the host's access list tight.

## Forensics

Every recovery invocation writes one immutable audit row. Query:

```sql
SELECT
  created_at,
  actor_email,
  target_id,
  metadata->>'target_email' AS target_email,
  metadata->'invoker'->>'hostname' AS invoked_from,
  metadata->'invoker'->>'os_user' AS os_user
FROM audit_logs
WHERE event_type = 'password_reset.recovery_issued'
ORDER BY created_at DESC;
```

The row survives user deletion — migration 000011 removed the FK on `actor_id`, so forensic history outlives the account.
