package users

import (
	"context"
	"net/http"
	"slices"

	"github.com/abdo75/Schlass/internal/httputil"
)

// DenialHandler is invoked from RequirePermission when an authenticated user
// lacks the required permission, immediately before the 403 response is
// written. Callers wire this from the router so the denial can be persisted
// to audit_logs. nil means "do not record."
//
// The handler receives the user, the permission they were missing, and the
// request itself so callers can extract method/path/IP for the audit row.
type DenialHandler func(ctx context.Context, user *User, requiredPerm string, r *http.Request)

// rolePermissions is v1 hardcoded. When v2 introduces dynamic RBAC this map
// becomes a DB lookup on roles / role_permissions; the permission strings
// themselves don't change, so handler gates + SPA usePermission() survive.
var rolePermissions = map[string][]string{
	"super_admin": {
		"audit.list",
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

// RequirePermission must chain AFTER the session-auth middleware. Returns 403
// FORBIDDEN on role miss, 401 INVALID_SESSION on no-user-in-context (wiring
// bug). Optional onDenied callback fires on the 403 path before the response
// is written; callers persist denials to audit_logs there. Pass nil in tests
// or for endpoints that should not audit denials.
func RequirePermission(perm string, onDenied DenialHandler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := CurrentUser(r.Context())
			if !ok {
				httputil.WriteError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
				return
			}
			if slices.Contains(PermissionsForRole(user.Role), perm) {
				next.ServeHTTP(w, r)
				return
			}
			if onDenied != nil {
				onDenied(r.Context(), user, perm, r)
			}
			httputil.WriteError(w, http.StatusForbidden, "FORBIDDEN", "This action requires a different permission.")
		})
	}
}
