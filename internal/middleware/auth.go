package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/abdo75/Schlass/internal/database"
	"github.com/abdo75/Schlass/internal/session"
	"github.com/abdo75/Schlass/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ctxKey int

const userCtxKey ctxKey = 0

// AuditLogger is the narrow contract the Auth middleware needs. *store.AuditStore
// satisfies it; integration tests swap in a fake that errors on Log. Duplicated
// from handler.AuditLogger (same shape) because middleware cannot import handler
// (handler imports middleware).
type AuditLogger interface {
	Log(ctx context.Context, q database.Querier, entry store.AuditEntry) error
}

// Auth is the middleware that enforces authentication on wrapped routes.
// See docs/superpowers/specs/2026-04-15-sprint2-login-design.md §2.
//
// Note on audit policy: session.revoked audit writes in this middleware
// are intentionally best-effort (return value ignored, ERROR-level slog
// on failure). This is the documented exception to the project-wide
// audit-in-tx rule. Making middleware revocation audit-in-tx would wedge
// every authed request on PG errors, trading availability for a duplicate
// audit row. The load-bearing compliance event is the original user-disable
// action at the source (in a Sprint 4+ admin handler), not the subsequent
// cleanup here. Do NOT "fix" this to audit-in-tx.
func Auth(
	sessionStore session.Store,
	userStore *store.UserStore,
	auditStore AuditLogger,
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
				_ = sessionStore.Delete(r.Context(), cookie.Value)
				writeAuthError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
				return
			}

			user, err := userStore.GetByID(r.Context(), pool, userID)
			if errors.Is(err, store.ErrUserNotFound) {
				_ = sessionStore.Delete(r.Context(), cookie.Value)
				if auditErr := auditStore.Log(r.Context(), pool, store.AuditEntry{
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

			if user.Status == "disabled" {
				_ = sessionStore.Delete(r.Context(), cookie.Value)
				if auditErr := auditStore.Log(r.Context(), pool, store.AuditEntry{
					EventType:  "session.revoked",
					ActorID:    &user.ID,
					ActorEmail: user.Email,
					TargetType: "user",
					TargetID:   user.ID.String(),
					IPAddress:  clientIP(r),
					Outcome:    "success",
					Metadata:   map[string]any{"reason": "user_disabled"},
				}); auditErr != nil {
					slog.Error("session.revoked audit write failed (best-effort)", "error", auditErr)
				}
				writeAuthError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
				return
			}

			ctx := context.WithValue(r.Context(), userCtxKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// CurrentUser returns the authenticated user from the request context.
// Returns (nil, false) if the request did not pass through the Auth middleware.
func CurrentUser(ctx context.Context) (*store.User, bool) {
	u, ok := ctx.Value(userCtxKey).(*store.User)
	return u, ok
}

func writeAuthError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   code,
		"message": message,
	})
}
