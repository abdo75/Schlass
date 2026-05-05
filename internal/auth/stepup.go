package auth

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdo75/Schlass/internal/audit"
	"github.com/abdo75/Schlass/internal/httputil"
	"github.com/abdo75/Schlass/internal/session"
	"github.com/abdo75/Schlass/internal/users"
)

// RequireRecentMFA rejects sensitive operations unless the current session
// has completed MFA within d. It must run after session auth; missing user or
// token is treated as an invalid-session wiring failure.
func RequireRecentMFA(d time.Duration, sessions session.Store, auditStore audit.Logger, pool *pgxpool.Pool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := users.CurrentUser(r.Context())
			if !ok {
				httputil.WriteError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
				return
			}
			token, ok := session.TokenFromContext(r.Context())
			if !ok {
				httputil.WriteError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
				return
			}
			sess, err := sessions.Get(r.Context(), token)
			if err != nil || sess == nil {
				if err != nil {
					slog.Warn("step-up: session lookup failed", "error", err)
				}
				httputil.WriteError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
				return
			}
			if sess.LastMFAAt.IsZero() || time.Since(sess.LastMFAAt) > d {
				emitStepUpAudit(r, pool, auditStore, user, "auth.stepup.required", "failure")
				httputil.WriteError(w, http.StatusUnauthorized, "STEPUP_REQUIRED", "Recent MFA verification is required.")
				return
			}
			emitStepUpAudit(r, pool, auditStore, user, "auth.stepup.satisfied", "success")
			next.ServeHTTP(w, r)
		})
	}
}

// emitStepUpAudit detaches the audit-of-audit write from the request lifecycle
// so a 401 rejection (or a successful protected call) doesn't block on a
// pool.Begin → Emit → Commit round-trip. Pre-extracts request-scoped values
// because the request ctx is canceled the instant we return to the caller.
func emitStepUpAudit(r *http.Request, pool *pgxpool.Pool, auditStore audit.Logger, user *users.User, eventType, outcome string) {
	if pool == nil || auditStore == nil {
		return
	}
	var actorID *uuid.UUID
	actorEmail := ""
	if user != nil {
		actorID = &user.ID
		actorEmail = user.Email
	}
	evt := audit.Event{
		EventType:  eventType,
		ActorID:    actorID,
		ActorEmail: actorEmail,
		TargetType: "http_endpoint",
		TargetID:   r.Method + " " + r.URL.Path,
		IPAddress:  extractClientIP(r),
		Outcome:    outcome,
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		tx, err := pool.Begin(ctx)
		if err != nil {
			slog.Warn("step-up audit: begin failed", "event_type", eventType, "error", err)
			return
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if err := auditStore.Emit(ctx, tx, evt); err != nil {
			slog.Warn("step-up audit: emit failed", "event_type", eventType, "error", err)
			return
		}
		if err := tx.Commit(ctx); err != nil {
			slog.Warn("step-up audit: commit failed", "event_type", eventType, "error", err)
		}
	}()
}
