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

// AuditLogger duplicated from handler.AuditLogger (middleware cannot import
// handler — handler imports middleware).
type AuditLogger interface {
	Log(ctx context.Context, q database.Querier, entry store.AuditEntry) error
}

// Auth middleware — session.revoked audit writes here are deliberately
// best-effort (return ignored, ERROR slog on failure). Making them
// audit-in-tx would wedge every authed request on PG errors. Load-bearing
// compliance event is the user-disable action in its source handler, not
// this cleanup. DO NOT "fix" to audit-in-tx.
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
				_ = sessionStore.Delete(r.Context(), sess.UserID, cookie.Value)
				writeAuthError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
				return
			}

			user, err := userStore.GetByID(r.Context(), pool, userID)
			if errors.Is(err, store.ErrUserNotFound) {
				_ = sessionStore.Delete(r.Context(), sess.UserID, cookie.Value)
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
				_ = sessionStore.Delete(r.Context(), user.ID.String(), cookie.Value)
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

// InjectUserForTest — unit test helper; never used in production code.
func InjectUserForTest(ctx context.Context, user *store.User) context.Context {
	return context.WithValue(ctx, userCtxKey, user)
}
