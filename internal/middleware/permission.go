package middleware

import (
	"net/http"
	"slices"
)

// rolePermissions is v1 hardcoded. When v2 introduces dynamic RBAC this map
// becomes a DB lookup on roles / role_permissions; the permission strings
// themselves don't change, so handler gates + SPA usePermission() survive.
var rolePermissions = map[string][]string{
	"super_admin": {
		"users.list",
		"users.read",
		"users.create",
		"users.update",
		"users.enable",
		"users.disable",
		"users.delete",
		"users.reset_password",
		"users.sessions.read",
		"users.sessions.terminate",
		"users.reset_mfa",
		"signing_keys.list",
		"signing_keys.rotate",
		"signing_keys.retire",
		"settings.read",
		"settings.write",
		"clients.list",
		"clients.read",
		"clients.create",
		"clients.update",
		"clients.disable",
		"clients.enable",
		"clients.rotate_secret",
		"clients.delete",
	},
	"user": {},
}

func PermissionsForRole(role string) []string {
	perms, ok := rolePermissions[role]
	if !ok {
		return []string{}
	}
	out := make([]string, len(perms))
	copy(out, perms)
	return out
}

// RequirePermission must chain AFTER middleware.Auth. Returns 403 FORBIDDEN
// on role miss, 401 INVALID_SESSION on no-user-in-context (wiring bug).
func RequirePermission(perm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := CurrentUser(r.Context())
			if !ok {
				writeAuthError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
				return
			}
			if slices.Contains(PermissionsForRole(user.Role), perm) {
				next.ServeHTTP(w, r)
				return
			}
			writeAuthError(w, http.StatusForbidden, "FORBIDDEN", "This action requires a different permission.")
		})
	}
}
