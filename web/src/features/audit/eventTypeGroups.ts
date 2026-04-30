// Grouped event-type catalog used by the EventTypePicker UI. Lives in its
// own module so `react-refresh/only-export-components` stays satisfied: the
// picker file exports a component only.

export type EventOption = { type: string; labelKey: string };
export type EventGroup = { groupKey: string; events: EventOption[] };

export const EVENT_TYPE_GROUPS: EventGroup[] = [
  { groupKey: "login", events: [{ type: "login.succeeded", labelKey: "login.succeeded" }, { type: "login.failed", labelKey: "login.failed" }, { type: "auth.permission_denied", labelKey: "auth.permission_denied" }] },
  { groupKey: "logout", events: [{ type: "logout.completed", labelKey: "logout.completed" }] },
  { groupKey: "account", events: [{ type: "account.locked", labelKey: "account.locked" }] },
  { groupKey: "mfaChallenge", events: [{ type: "mfa.challenge_succeeded", labelKey: "mfa.challenge_succeeded" }, { type: "mfa.challenge_failed", labelKey: "mfa.challenge_failed" }, { type: "mfa.recovery_code_used", labelKey: "mfa.recovery_code_used" }] },
  { groupKey: "mfaEnrollment", events: [{ type: "mfa.enrollment_completed", labelKey: "mfa.enrollment_completed" }, { type: "mfa.reset", labelKey: "mfa.reset" }, { type: "mfa.self_reset", labelKey: "mfa.self_reset" }] },
  { groupKey: "password", events: [{ type: "password.changed", labelKey: "password.changed" }] },
  { groupKey: "passwordReset", events: [{ type: "password_reset.requested", labelKey: "passwordReset.requested" }, { type: "password_reset.completed", labelKey: "passwordReset.completed" }, { type: "password_reset.confirm_failed", labelKey: "passwordReset.confirm_failed" }, { type: "password_reset.admin_blocked", labelKey: "passwordReset.admin_blocked" }, { type: "password_reset.cleanup_swept", labelKey: "passwordReset.cleanup_swept" }] },
  { groupKey: "session", events: [{ type: "session.revoked", labelKey: "session.revoked" }, { type: "session.terminated", labelKey: "session.terminated" }, { type: "session.reauth_forced", labelKey: "session.reauth_forced" }] },
  { groupKey: "userManagement", events: [{ type: "user.created", labelKey: "user.created" }, { type: "user.updated", labelKey: "user.updated" }, { type: "user.enabled", labelKey: "user.enabled" }, { type: "user.disabled", labelKey: "user.disabled" }, { type: "user.deleted", labelKey: "user.deleted" }, { type: "user.password_reset", labelKey: "user.password_reset" }, { type: "user.sessions_terminated", labelKey: "user.sessions_terminated" }, { type: "user.audit_pseudonymized", labelKey: "user.audit_pseudonymized" }] },
  { groupKey: "userTokenRevocation", events: [{ type: "user.revoke_before_set", labelKey: "user.revoke_before_set" }, { type: "user.revoke_before_enforced", labelKey: "user.revoke_before_enforced" }] },
  { groupKey: "clientManagement", events: [{ type: "client.created", labelKey: "client.created" }, { type: "client.name_updated", labelKey: "client.name_updated" }, { type: "client.redirect_uris_updated", labelKey: "client.redirect_uris_updated" }, { type: "client.scopes_updated", labelKey: "client.scopes_updated" }, { type: "client.grants_updated", labelKey: "client.grants_updated" }, { type: "client.enabled", labelKey: "client.enabled" }, { type: "client.disabled", labelKey: "client.disabled" }, { type: "client.secret_rotated", labelKey: "client.secret_rotated" }, { type: "client.deleted", labelKey: "client.deleted" }] },
  { groupKey: "oidcAuthorize", events: [{ type: "oidc.authorize.succeeded", labelKey: "oidcAuthorize.succeeded" }, { type: "oidc.authorize.invalid_request", labelKey: "oidcAuthorize.invalid_request" }] },
  { groupKey: "oidcClient", events: [{ type: "oidc.client.auth_failed", labelKey: "oidcClient.auth_failed" }] },
  { groupKey: "oidcCode", events: [{ type: "oidc.code.exchanged", labelKey: "oidcCode.exchanged" }, { type: "oidc.code.client_mismatch", labelKey: "oidcCode.client_mismatch" }, { type: "oidc.code.redirect_mismatch", labelKey: "oidcCode.redirect_mismatch" }, { type: "oidc.code.pkce_mismatch", labelKey: "oidcCode.pkce_mismatch" }, { type: "oidc.code.user_not_found", labelKey: "oidcCode.user_not_found" }, { type: "oidc.code.user_disabled", labelKey: "oidcCode.user_disabled" }, { type: "oidc.code.grant_removed", labelKey: "oidcCode.grant_removed" }, { type: "oidc.code.scope_removed", labelKey: "oidcCode.scope_removed" }, { type: "oidc.code.replay_detected", labelKey: "oidcCode.replay_detected" }] },
  { groupKey: "oidcRefresh", events: [{ type: "oidc.token.refreshed", labelKey: "oidcRefresh.refreshed" }, { type: "oidc.refresh.reuse_detected", labelKey: "oidcRefresh.reuse_detected" }, { type: "oidc.refresh.user_disabled", labelKey: "oidcRefresh.user_disabled" }] },
  { groupKey: "oidcUserinfo", events: [{ type: "oidc.userinfo.accessed", labelKey: "oidcUserinfo.accessed" }] },
  { groupKey: "signingKey", events: [{ type: "oidc.signing_key.generated", labelKey: "signingKey.generated" }, { type: "oidc.signing_key.rotated", labelKey: "signingKey.rotated" }, { type: "oidc.signing_key.retired", labelKey: "signingKey.retired" }] },
  { groupKey: "configuration", events: [
    { type: "config.instance_name.changed", labelKey: "config.instance_name" },
    { type: "config.mfa_required.changed", labelKey: "config.mfa_required" },
    { type: "config.password_min_length.changed", labelKey: "config.password_min_length" },
    { type: "config.password_require_upper.changed", labelKey: "config.password_require_upper" },
    { type: "config.password_require_digit.changed", labelKey: "config.password_require_digit" },
    { type: "config.lockout_threshold.changed", labelKey: "config.lockout_threshold" },
    { type: "config.lockout_duration_secs.changed", labelKey: "config.lockout_duration_secs" },
    { type: "config.access_token_ttl_secs.changed", labelKey: "config.access_token_ttl_secs" },
    { type: "config.refresh_token_ttl_secs.changed", labelKey: "config.refresh_token_ttl_secs" },
    { type: "config.smtp_host.changed", labelKey: "config.smtp_host" },
    { type: "config.smtp_port.changed", labelKey: "config.smtp_port" },
    { type: "config.smtp_username.changed", labelKey: "config.smtp_username" },
    { type: "config.smtp_from.changed", labelKey: "config.smtp_from" },
    { type: "config.smtp_password.changed", labelKey: "config.smtp_password" },
    { type: "config.audit_view_logging_enabled.changed", labelKey: "config.audit_view_logging_enabled" },
    { type: "config.audit_export_max_rows.changed", labelKey: "config.audit_export_max_rows" },
  ] },
  { groupKey: "setup", events: [{ type: "setup.completed", labelKey: "setup.completed" }] },
  { groupKey: "audit", events: [{ type: "audit.viewed", labelKey: "audit.viewed" }, { type: "audit.exported", labelKey: "audit.exported" }] },
];
