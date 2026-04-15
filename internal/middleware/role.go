package middleware

import (
	"context"
	"net/http"

	"github.com/abdo75/Schlass/internal/store"
)

// InjectUserForTest lets tests populate the request context with a user
// without going through the real Auth middleware. Only intended for unit
// tests of downstream middleware like RequireRole.
func InjectUserForTest(ctx context.Context, user *store.User) context.Context {
	return context.WithValue(ctx, userCtxKey, user)
}

// RequireRole returns a middleware that enforces that the authenticated user
// has one of the listed roles. Must be chained AFTER middleware.Auth (which
// injects the user into the request context). Returns 403 FORBIDDEN if the
// user's role is not allowed, 401 INVALID_SESSION if no user is in context
// (indicating a wiring bug).
//
// See docs/superpowers/specs/2026-04-15-sprint3-user-management-design.md §2.1.
func RequireRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := CurrentUser(r.Context())
			if !ok {
				writeAuthError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
				return
			}
			for _, allowed := range roles {
				if user.Role == allowed {
					next.ServeHTTP(w, r)
					return
				}
			}
			writeAuthError(w, http.StatusForbidden, "FORBIDDEN", "This action requires a different role.")
		})
	}
}
