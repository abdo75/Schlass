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

// OptionalAuth is like Auth but never rejects on missing session cookie:
// unauthenticated requests pass through with no user in ctx. Sessions that
// are present but invalid (session store error, orphan user, disabled user)
// ARE still revoked with the same `session.revoked` best-effort audit as
// Auth — they just don't 401 at the end, they pass through unauthenticated.
//
// Consumed by the /authorize handler which must distinguish "no session →
// redirect to /login" from "session present → issue a code". Disabled users
// arriving with a stale cookie get cleaned up on the way through so
// /authorize sees them as unauthenticated and redirects them to re-auth;
// the session.revoked audit row preserves the compliance trail.
//
// Session store transport errors (not ErrNotFound — genuine Valkey failure)
// also cause pass-through rather than 503. The /authorize handler has no
// business returning 503 because Valkey is blipping; it can still either
// redirect the user to /login (if they had no session) or serve them as
// anonymous and let them re-enter the site. An ERROR-level slog records it.
//
// The session.revoked audit rows emitted here carry metadata.mw="optional"
// so they can be distinguished from the same event in the Auth middleware.
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

// clearSessionCookie emits a Set-Cookie that deletes the client's
// schlass_session cookie. Used when OptionalAuth detects an invalid or
// revoked session — the browser should not keep trying to present it.
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
