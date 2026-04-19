package middleware

import (
	"net/http"
	"slices"
)

// rolePermissions is the v1 hardcoded mapping from role string to the set of
// permissions that role holds. super_admin → all; user → none.
//
// When v2 introduces dynamic RBAC (see docs/v1-scope.md line 33, "Org Admin
// deferred to v2"), this map is replaced by a lookup into a roles /
// role_permissions table. The permission strings themselves do not change —
// handler gates and SPA usePermission() calls survive the migration
// unchanged.
//
// Package-level var (not constant map) so tests in the same package could
// override it if needed; production code must never mutate it.
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

// PermissionsForRole returns the permissions held by the given role. Returns
// an empty slice for unknown roles (defensive: an unrecognised role grants
// nothing).
func PermissionsForRole(role string) []string {
	perms, ok := rolePermissions[role]
	if !ok {
		return []string{}
	}
	// Return a copy so callers cannot mutate the package-level map.
	out := make([]string, len(perms))
	copy(out, perms)
	return out
}

// RequirePermission returns a middleware that enforces the authenticated user
// holds the named permission. Must be chained AFTER middleware.Auth (which
// injects the user into the request context). Returns 403 FORBIDDEN if the
// user's role does not grant the permission, 401 INVALID_SESSION if no user
// is in context (indicating a wiring bug).
//
// V1 resolves the role→permissions mapping in-process via rolePermissions.
// V2 will resolve via a DB lookup; the handler-side permission string does
// not change across that migration.
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
