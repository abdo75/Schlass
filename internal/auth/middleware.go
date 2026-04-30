package auth

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdo75/Schlass/internal/audit"
	"github.com/abdo75/Schlass/internal/session"
	"github.com/abdo75/Schlass/internal/users"
)

// CurrentUser retrieves the authenticated user injected by Middleware or
// BearerAuth. Returns (nil, false) when the request is unauthenticated.
func CurrentUser(ctx context.Context) (*users.User, bool) {
	return users.CurrentUser(ctx)
}

// Middleware — session.revoked audit writes here are deliberately
// best-effort (return ignored, ERROR slog on failure). Making them
// audit-in-tx would wedge every authed request on PG errors. Load-bearing
// compliance event is the user-disable action in its source handler, not
// this cleanup. DO NOT "fix" to audit-in-tx.
func Middleware(
	sessionStore session.Store,
	userStore *users.Store,
	auditStore audit.Logger,
	pool *pgxpool.Pool,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("schlass_session")
			if err != nil {
				writeAuthError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
				return
			}

			sess, err := sessionStore.Get(r.Context(), cookie.Value)
			if errors.Is(err, session.ErrNotFound) {
				writeAuthError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
				return
			}
			if err != nil {
				slog.Warn("session store error (likely Valkey transient)", "error", err)
				writeAuthError(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "Service temporarily unavailable.")
				return
			}

			userID, parseErr := uuid.Parse(sess.UserID)
			if parseErr != nil {
				slog.Error("session contained invalid user_id", "error", parseErr)
				_ = sessionStore.Delete(r.Context(), sess.UserID, cookie.Value)
				writeAuthError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
				return
			}

			u, err := userStore.GetByID(r.Context(), pool, userID)
			if errors.Is(err, users.ErrUserNotFound) {
				_ = sessionStore.Delete(r.Context(), sess.UserID, cookie.Value)
				if auditErr := auditStore.Log(r.Context(), pool, audit.Entry{
					EventType:  "session.revoked",
					ActorEmail: "",
					TargetType: "user",
					TargetID:   userID.String(),
					IPAddress:  clientIP(r),
					Outcome:    "success",
					Metadata:   map[string]any{"reason": "user_not_found"},
				}); auditErr != nil {
					slog.Error("session.revoked audit write failed (best-effort)", "error", auditErr)
				}
				writeAuthError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
				return
			}
			if err != nil {
				slog.Error("GetByID in auth middleware failed", "error", err)
				writeAuthError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
				return
			}

			if u.Status == "disabled" {
				_ = sessionStore.Delete(r.Context(), u.ID.String(), cookie.Value)
				if auditErr := auditStore.Log(r.Context(), pool, audit.Entry{
					EventType:  "session.revoked",
					ActorID:    &u.ID,
					ActorEmail: u.Email,
					TargetType: "user",
					TargetID:   u.ID.String(),
					IPAddress:  clientIP(r),
					Outcome:    "success",
					Metadata:   map[string]any{"reason": "user_disabled"},
				}); auditErr != nil {
					slog.Error("session.revoked audit write failed (best-effort)", "error", auditErr)
				}
				writeAuthError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
				return
			}

			ctx := session.WithToken(users.WithCurrentUser(r.Context(), u), cookie.Value)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func writeAuthError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   code,
		"message": message,
	})
}

func clientIP(r *http.Request) string {
	return extractClientIP(r)
}
