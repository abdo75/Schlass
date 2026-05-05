// Permission strings mirror the backend permission catalog in
// internal/middleware/permission.go. Today the role→permission mapping is
// hardcoded in both places; v2 will fetch it from /api/permissions once
// dynamic RBAC lands (see docs/v1-scope.md line 33, "Org Admin deferred to
// v2"). Consumers import constants from here rather than typing raw strings
// so rename migrations are a single-file change.
export const PERMISSIONS = {
  AUDIT_VIEW: "audit.view",
  AUDIT_EXPORT: "audit.export",
  AUDIT_ADMIN: "audit.admin",
  USERS_LIST: "users.list",
  USERS_READ: "users.read",
  USERS_CREATE: "users.create",
  USERS_UPDATE: "users.update",
  USERS_ENABLE: "users.enable",
  USERS_DISABLE: "users.disable",
  USERS_DELETE: "users.delete",
  USERS_RESET_PASSWORD: "users.reset_password",
  USERS_SESSIONS_READ: "users.sessions.read",
  USERS_SESSIONS_TERMINATE: "users.sessions.terminate",
  USERS_RESET_MFA: "users.reset_mfa",
  SIGNING_KEYS_ROTATE: "signing_keys.rotate",
  SIGNING_KEYS_RETIRE: "signing_keys.retire",
  SETTINGS_READ: "settings.read",
  SETTINGS_WRITE: "settings.write",
} as const;

export type Permission = (typeof PERMISSIONS)[keyof typeof PERMISSIONS];

const ROLE_PERMISSIONS: Record<string, ReadonlyArray<Permission>> = {
  super_admin: Object.values(PERMISSIONS),
  user: [],
};

export function permissionsForRole(role: string): ReadonlyArray<Permission> {
  return ROLE_PERMISSIONS[role] ?? [];
}
