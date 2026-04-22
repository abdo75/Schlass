package middleware

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdo75/Schlass/internal/session"
	"github.com/abdo75/Schlass/internal/store"
)

// OptionalAuth passes through on missing/invalid cookie; still revokes
// orphan/disabled-user sessions on the way through (best-effort audit as
// in Auth, with metadata.mw="optional" to distinguish). Session store
// transport errors pass through (not 503) — /authorize can still redirect
// to /login or serve anonymously. Consumed by /authorize to distinguish
// "no session → /login" from "session present → issue code".
func OptionalAuth(
	sessionStore session.Store,
	userStore *store.UserStore,
	auditStore AuditLogger,
	pool *pgxpool.Pool,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("schlass_session")
			if err != nil || cookie.Value == "" {
				next.ServeHTTP(w, r)
				return
			}

			sess, err := sessionStore.Get(r.Context(), cookie.Value)
			if errors.Is(err, session.ErrNotFound) {
				clearSessionCookie(w)
				next.ServeHTTP(w, r)
				return
			}
			if err != nil {
				slog.Error("OptionalAuth: session store error (treating as unauthenticated)", "error", err)
				next.ServeHTTP(w, r)
				return
			}

			userID, parseErr := uuid.Parse(sess.UserID)
			if parseErr != nil {
				slog.Error("OptionalAuth: session contained invalid user_id", "error", parseErr)
				_ = sessionStore.Delete(r.Context(), sess.UserID, cookie.Value)
				clearSessionCookie(w)
				next.ServeHTTP(w, r)
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
					Metadata:   map[string]any{"reason": "user_not_found", "mw": "optional"},
				}); auditErr != nil {
					slog.Error("OptionalAuth: session.revoked audit write failed (best-effort)", "error", auditErr)
				}
				clearSessionCookie(w)
				next.ServeHTTP(w, r)
				return
			}
			if err != nil {
				slog.Error("OptionalAuth: GetByID failed (treating as unauthenticated)", "error", err)
				next.ServeHTTP(w, r)
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
					Metadata:   map[string]any{"reason": "user_disabled", "mw": "optional"},
				}); auditErr != nil {
					slog.Error("OptionalAuth: session.revoked audit write failed (best-effort)", "error", auditErr)
				}
				clearSessionCookie(w)
				next.ServeHTTP(w, r)
				return
			}

			ctx := context.WithValue(r.Context(), userCtxKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "schlass_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}
