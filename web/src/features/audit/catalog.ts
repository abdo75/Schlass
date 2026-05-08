export type Severity = "normal" | "critical";

export interface RenderedSentence {
  text: string;
  fallback: boolean;
}

export const EVENT_TYPES_KNOWN = [
  "login.succeeded",
  "login.failed",
  "auth.permission_denied",
  "logout.completed",
  "account.locked",
  "mfa.enrollment_completed",
  "mfa.challenge_succeeded",
  "mfa.challenge_failed",
  "mfa.recovery_code_used",
  "mfa.self_reset",
  "mfa.reset",
  "password.changed",
  "password_reset.admin_blocked",
  "password_reset.requested",
  "password_reset.completed",
  "password_reset.confirm_failed",
  "password_reset.cleanup_swept",
  "session.revoked",
  "session.reauth_forced",
  "session.terminated",
  "user.created",
  "user.updated",
  "user.enabled",
  "user.disabled",
  "user.deleted",
  "user.password_reset",
  "user.sessions_terminated",
  "user.audit_pseudonymized",
  "user.revoke_before_set",
  "user.revoke_before_enforced",
  "client.created",
  "client.name_updated",
  "client.redirect_uris_updated",
  "client.scopes_updated",
  "client.grants_updated",
  "client.disabled",
  "client.enabled",
  "client.secret_rotated",
  "client.deleted",
  "oidc.authorize.succeeded",
  "oidc.authorize.invalid_request",
  "oidc.client.auth_failed",
  "oidc.code.client_mismatch",
  "oidc.code.redirect_mismatch",
  "oidc.code.pkce_mismatch",
  "oidc.code.user_not_found",
  "oidc.code.user_disabled",
  "oidc.code.grant_removed",
  "oidc.code.scope_removed",
  "oidc.code.exchanged",
  "oidc.code.replay_detected",
  "oidc.refresh.reuse_detected",
  "oidc.refresh.user_disabled",
  "oidc.token.refreshed",
  "oidc.userinfo.accessed",
  "oidc.signing_key.generated",
  "oidc.signing_key.rotated",
  "oidc.signing_key.retired",
  "setup.completed",
  "audit.viewed",
  "audit.exported",
] as const;

const CRITICAL_EVENTS = new Set<string>([
  "oidc.refresh.reuse_detected",
  "oidc.code.replay_detected",
  "oidc.code.client_mismatch",
  "oidc.code.pkce_mismatch",
  "oidc.code.redirect_mismatch",
  "client.secret_rotated",
  "client.deleted",
  "oidc.signing_key.rotated",
  "oidc.signing_key.retired",
  "user.revoke_before_set",
  "account.locked",
]);

export function severity(eventType: string, _metadata: Record<string, unknown>): Severity {
  return CRITICAL_EVENTS.has(eventType) ? "critical" : "normal";
}

function asString(v: unknown, fallback = ""): string {
  return typeof v === "string" ? v : typeof v === "number" || typeof v === "boolean" ? String(v) : fallback;
}

export function renderSentence(
  eventType: string,
  m: Record<string, unknown>,
  actorDisplay: string,
  targetDisplay: string | null,
): RenderedSentence {
  const target = targetDisplay ?? "the target";
  if (eventType.startsWith("config.") && eventType.endsWith(".changed")) {
    return ok(`${actorDisplay} changed the ${eventType.slice(7, -8)} setting.`);
  }
  switch (eventType) {
    case "login.succeeded": return ok(`${actorDisplay} signed in.`);
    case "login.failed": return ok(`Sign-in failed for ${actorDisplay}.`);
    case "auth.permission_denied": {
      const perm = targetDisplay ?? "an admin permission";
      const method = asString(m.method);
      const path = asString(m.path);
      const where = method && path ? ` while attempting ${method} ${path}` : "";
      return ok(`${actorDisplay} was denied the ${perm} permission${where}.`);
    }
    case "logout.completed": return ok(`${actorDisplay} signed out.`);
    case "account.locked": return ok(`The account ${actorDisplay} was locked.`);
    case "mfa.enrollment_completed": return ok(`${actorDisplay} enrolled multi-factor authentication.`);
    case "mfa.challenge_succeeded": return ok(`${actorDisplay} passed the multi-factor challenge.`);
    case "mfa.challenge_failed": return ok(`${actorDisplay} failed the multi-factor challenge.`);
    case "mfa.recovery_code_used": return ok(`${actorDisplay} used a recovery code.`);
    case "mfa.self_reset": return ok(`${actorDisplay} reset their own multi-factor authentication.`);
    case "mfa.reset": return ok(`${actorDisplay} reset multi-factor authentication for ${target}.`);
    case "password.changed": return ok(`${actorDisplay} changed their password.`);
    case "password_reset.admin_blocked": return ok(`A password-reset attempt for ${actorDisplay} was blocked.`);
    case "password_reset.requested": return ok(`A password reset was requested for ${target}.`);
    case "password_reset.completed": return ok(`${actorDisplay} completed a password reset.`);
    case "password_reset.confirm_failed": return ok(`A password-reset confirmation attempt failed.`);
    case "password_reset.cleanup_swept": return ok(`The cleanup sweeper removed stale password-reset data.`);
    case "session.revoked": return ok(`A session was revoked for ${actorDisplay}.`);
    case "session.reauth_forced": return ok(`${actorDisplay} was asked to re-authenticate.`);
    case "session.terminated": return ok(`${actorDisplay} terminated a session.`);
    case "user.created": return ok(`${actorDisplay} created the user ${target}.`);
    case "user.updated": return ok(`${actorDisplay} updated the user ${target}.`);
    case "user.enabled": return ok(`${actorDisplay} enabled the user ${target}.`);
    case "user.disabled": return ok(`${actorDisplay} disabled the user ${target}.`);
    case "user.deleted": return ok(`${actorDisplay} deleted the user ${target}.`);
    case "user.password_reset": return ok(`${actorDisplay} sent a password reset to ${target}.`);
    case "user.sessions_terminated": return ok(`${actorDisplay} terminated all sessions for ${target}.`);
    case "user.audit_pseudonymized": return ok(`${actorDisplay} pseudonymized audit history.`);
    case "user.revoke_before_set": return ok(`${actorDisplay} invalidated existing tokens for ${target}.`);
    case "user.revoke_before_enforced": return ok(`A token for ${actorDisplay} was rejected.`);
    case "client.created": return ok(`${actorDisplay} registered the client ${target}.`);
    case "client.name_updated": return ok(`${actorDisplay} renamed the client ${target}.`);
    case "client.redirect_uris_updated": return ok(`${actorDisplay} updated redirect URIs for ${target}.`);
    case "client.scopes_updated": return ok(`${actorDisplay} updated scopes for ${target}.`);
    case "client.grants_updated": return ok(`${actorDisplay} updated grants for ${target}.`);
    case "client.disabled": return ok(`${actorDisplay} disabled the client ${target}.`);
    case "client.enabled": return ok(`${actorDisplay} enabled the client ${target}.`);
    case "client.secret_rotated": return ok(`${actorDisplay} rotated the client secret for ${target}.`);
    case "client.deleted": return ok(`${actorDisplay} deleted the client ${target}.`);
    case "oidc.authorize.succeeded": return ok(`${actorDisplay} authorized ${target}.`);
    case "oidc.authorize.invalid_request": return ok(`An OIDC authorize request to ${target} was rejected.`);
    case "oidc.client.auth_failed": return ok(`The client ${target} failed to authenticate.`);
    case "oidc.code.client_mismatch": return ok(`An authorization-code exchange for ${target} used the wrong client.`);
    case "oidc.code.redirect_mismatch": return ok(`An authorization-code exchange for ${target} used the wrong redirect URI.`);
    case "oidc.code.pkce_mismatch": return ok(`An authorization-code exchange for ${target} failed PKCE verification.`);
    case "oidc.code.user_not_found": return ok(`An authorization-code exchange for ${target} referenced a missing user.`);
    case "oidc.code.user_disabled": return ok(`An authorization-code exchange for ${target} referenced a disabled user.`);
    case "oidc.code.grant_removed": return ok(`An authorization-code exchange for ${target} used a removed grant.`);
    case "oidc.code.scope_removed": return ok(`An authorization-code exchange for ${target} used removed scopes.`);
    case "oidc.code.exchanged": return ok(`${actorDisplay} exchanged an authorization code for ${target}.`);
    case "oidc.code.replay_detected": return ok(`An authorization code was replayed for ${target}.`);
    case "oidc.refresh.reuse_detected": return ok(`A refresh token was reused for ${target}.`);
    case "oidc.refresh.user_disabled": return ok(`A refresh request for ${target} was refused because the user is disabled.`);
    case "oidc.token.refreshed": return ok(`${actorDisplay} refreshed an access token for ${target}.`);
    case "oidc.userinfo.accessed": return ok(`${actorDisplay} read userinfo through ${target}.`);
    case "oidc.signing_key.generated": return ok(`The system generated a signing key.`);
    case "oidc.signing_key.rotated": return ok(`${actorDisplay} rotated the active signing key.`);
    case "oidc.signing_key.retired": return ok(`${actorDisplay} retired a signing key.`);
    case "setup.completed": return ok(`${actorDisplay} completed initial setup.`);
    case "audit.viewed": return ok(`${actorDisplay} opened the audit log.`);
    case "audit.exported": return ok(`${actorDisplay} exported the audit log as ${asString(m.format, "file").toUpperCase()} (${asString(m.row_count, "0")} rows).`);
    default: return { text: `${eventType} by ${actorDisplay}`, fallback: true };
  }
}

export type LookupResult =
  | { fallback: false; key: string; raw: string; secondary?: string }
  | { fallback: true; key: null; raw: string; secondary?: string };

export function lookupReason(eventType: string, m: Record<string, unknown>): LookupResult {
  if (eventType === "login.failed" && m.reason === "wrong_password") {
    return { key: "audit.reason.login.wrong_password", raw: "wrong_password", fallback: false };
  }
  if (eventType === "oidc.authorize.invalid_request" && m.oauth_error === "invalid_scope") {
    return { key: "audit.reason.oidcAuthorizeInvalidRequest.invalid_scope", raw: "invalid_scope", secondary: asString(m.reason), fallback: false };
  }
  return { key: null, raw: asString(m.reason) || asString(m.oauth_error), fallback: true };
}

export function lookupAlert(eventType: string): string | null {
  return eventType === "account.locked" || eventType === "oidc.refresh.reuse_detected"
    ? `audit.alert.${eventType}`
    : null;
}

export function lookupHint(configKey: string, from: unknown, to: unknown): { key: string } {
  if (configKey === "audit_export_max_rows" && Number(to) === 0) return { key: "audit.hint.audit_export_max_rows.uncapped" };
  return { key: `audit.hint.${configKey}.${Number(to) > Number(from) ? "up" : "down"}` };
}

function ok(text: string): RenderedSentence {
  return { text, fallback: false };
}
