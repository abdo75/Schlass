package auth

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdo75/Schlass/internal/audit"
	"github.com/abdo75/Schlass/internal/session"
	"github.com/abdo75/Schlass/internal/users"
)

// OptionalMiddleware passes through on missing/invalid cookie; still revokes
// orphan/disabled-user sessions on the way through (best-effort audit as
// in Middleware, with metadata.mw="optional" to distinguish). Session store
// transport errors pass through (not 503) — /authorize can still redirect
// to /login or serve anonymously. Consumed by /authorize to distinguish
// "no session → /login" from "session present → issue code".
func OptionalMiddleware(
	sessionStore session.Store,
	userStore *users.Store,
	auditStore audit.Logger,
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
				slog.Error("OptionalMiddleware: session store error (treating as unauthenticated)", "error", err)
				next.ServeHTTP(w, r)
				return
			}

			userID, parseErr := uuid.Parse(sess.UserID)
			if parseErr != nil {
				slog.Error("OptionalMiddleware: session contained invalid user_id", "error", parseErr)
				_ = sessionStore.Delete(r.Context(), sess.UserID, cookie.Value)
				clearSessionCookie(w)
				next.ServeHTTP(w, r)
				return
			}

			u, err := userStore.GetByID(r.Context(), pool, userID)
			if errors.Is(err, users.ErrUserNotFound) {
				_ = sessionStore.Delete(r.Context(), sess.UserID, cookie.Value)
				bestEffortAudit(r.Context(), pool, auditStore, audit.Event{
					EventType:      "session.revoked",
					TargetType:     "user",
					TargetID:       userID.String(),
					IPAddress:      clientIP(r),
					ClientUAFamily: audit.ParseUAFamily(r.Header.Get("User-Agent")),
					Outcome:        "success",
					Metadata:       map[string]any{"reason": "user_not_found", "mw": "optional"},
				})
				clearSessionCookie(w)
				next.ServeHTTP(w, r)
				return
			}
			if err != nil {
				slog.Error("OptionalMiddleware: GetByID failed (treating as unauthenticated)", "error", err)
				next.ServeHTTP(w, r)
				return
			}

			if u.Status == "disabled" {
				_ = sessionStore.Delete(r.Context(), u.ID.String(), cookie.Value)
				bestEffortAudit(r.Context(), pool, auditStore, audit.Event{
					EventType:      "session.revoked",
					ActorID:        &u.ID,
					ActorEmail:     u.Email,
					TargetType:     "user",
					TargetID:       u.ID.String(),
					IPAddress:      clientIP(r),
					ClientUAFamily: audit.ParseUAFamily(r.Header.Get("User-Agent")),
					Outcome:        "success",
					Metadata:       map[string]any{"reason": "user_disabled", "mw": "optional"},
				})
				clearSessionCookie(w)
				next.ServeHTTP(w, r)
				return
			}

			ctx := users.WithCurrentUser(r.Context(), u)
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
