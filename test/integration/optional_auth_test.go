//go:build integration

package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/abdo75/Schlass/internal/audit"
	"github.com/abdo75/Schlass/internal/auth"
	"github.com/abdo75/Schlass/internal/users"
)

// optionalAuthProbeHandler records whether CurrentUser was set by OptionalAuth.
func optionalAuthProbeHandler(got **users.User) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, _ := auth.CurrentUser(r.Context())
		*got = u
		w.WriteHeader(http.StatusOK)
	})
}

func TestOptionalAuth_NoCookiePassesThrough(t *testing.T) {
	env := NewTestEnv(t)
	mw := auth.OptionalMiddleware(env.SessionStore, env.UserStore, audit.NewStore(), env.Pool)
	var got *users.User
	h := mw(optionalAuthProbeHandler(&got))

	req := httptest.NewRequestWithContext(t.Context(), "GET", "/authorize", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want 200 (pass-through)", rec.Code)
	}
	if got != nil {
		t.Fatal("should have no user in ctx when cookie absent")
	}
}

func TestOptionalAuth_ValidSessionInjectsUser(t *testing.T) {
	env := NewTestEnv(t)
	env.SeedAdmin(t, "a@example.com", "CorrectHorse1Battery")
	cookie := env.LoginAsAdmin(t, "a@example.com", "CorrectHorse1Battery")

	mw := auth.OptionalMiddleware(env.SessionStore, env.UserStore, audit.NewStore(), env.Pool)
	var got *users.User
	h := mw(optionalAuthProbeHandler(&got))

	req := httptest.NewRequestWithContext(t.Context(), "GET", "/authorize", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if got == nil {
		t.Fatal("expected user in ctx")
	}
	if got.Email != "a@example.com" {
		t.Fatalf("wrong user: %s", got.Email)
	}
}

func TestOptionalAuth_OrphanSessionRevokes(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()
	env.SeedAdmin(t, "ghost@example.com", "CorrectHorse1Battery")
	cookie := env.LoginAsAdmin(t, "ghost@example.com", "CorrectHorse1Battery")

	// Delete user directly — session remains in Valkey.
	userID := env.GetUserIDByEmail(t, "ghost@example.com")
	_, _ = env.Pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, userID)

	mw := auth.OptionalMiddleware(env.SessionStore, env.UserStore, audit.NewStore(), env.Pool)
	var got *users.User
	h := mw(optionalAuthProbeHandler(&got))

	req := httptest.NewRequestWithContext(t.Context(), "GET", "/authorize", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want 200 (pass-through)", rec.Code)
	}
	if got != nil {
		t.Fatal("should have no user in ctx after revoke")
	}

	// Audit row must exist.
	var count int
	_ = env.Pool.QueryRow(ctx, `
		SELECT count(*) FROM audit_logs
		WHERE event_type='session.revoked'
		  AND metadata->>'reason'='user_not_found'
		  AND metadata->>'mw'='optional'
	`).Scan(&count)
	if count != 1 {
		t.Fatalf("expected 1 session.revoked audit row (mw=optional), got %d", count)
	}

	// Session must be gone from Valkey.
	if _, err := env.SessionStore.Get(ctx, cookie.Value); err == nil {
		t.Fatal("session still in valkey after revoke")
	}
}

func TestOptionalAuth_DisabledUserRevokes(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()
	env.SeedAdmin(t, "d@example.com", "CorrectHorse1Battery")
	cookie := env.LoginAsAdmin(t, "d@example.com", "CorrectHorse1Battery")

	userID := env.GetUserIDByEmail(t, "d@example.com")
	_, _ = env.Pool.Exec(ctx, `UPDATE users SET status='disabled' WHERE id=$1`, userID)

	mw := auth.OptionalMiddleware(env.SessionStore, env.UserStore, audit.NewStore(), env.Pool)
	var got *users.User
	h := mw(optionalAuthProbeHandler(&got))

	req := httptest.NewRequestWithContext(t.Context(), "GET", "/authorize", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if got != nil {
		t.Fatal("should have no user in ctx for disabled user")
	}

	var count int
	_ = env.Pool.QueryRow(ctx, `
		SELECT count(*) FROM audit_logs
		WHERE event_type='session.revoked'
		  AND metadata->>'reason'='user_disabled'
		  AND metadata->>'mw'='optional'
		  AND target_id=$1
	`, userID.String()).Scan(&count)
	if count != 1 {
		t.Fatalf("expected 1 session.revoked audit row, got %d", count)
	}
}

func TestOptionalAuth_InvalidUUIDInSessionPassesThrough(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()

	// Manually set a session with a garbage user_id. The JSON must be valid
	// (session.Get uses json.Unmarshal) but the user_id must not be a UUID,
	// so the middleware reaches uuid.Parse and fails there.
	_ = env.Valkey.Set(ctx, "session:garbage-token",
		`{"user_id":"not-a-uuid","created_at":"2026-01-01T00:00:00Z","last_seen_at":"2026-01-01T00:00:00Z","ip_address":"","user_agent":""}`,
		0).Err()

	mw := auth.OptionalMiddleware(env.SessionStore, env.UserStore, audit.NewStore(), env.Pool)
	var got *users.User
	h := mw(optionalAuthProbeHandler(&got))

	req := httptest.NewRequestWithContext(t.Context(), "GET", "/authorize", nil)
	req.AddCookie(&http.Cookie{Name: "schlass_session", Value: "garbage-token"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if got != nil {
		t.Fatal("invalid uuid should not inject user")
	}

	// The response must include a Set-Cookie that clears the session.
	cleared := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == "schlass_session" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("expected Set-Cookie clearing the session")
	}

	// Sentinel: confirm uuid.Nil is the zero value (not related to the test logic,
	// just ensures the uuid import is used).
	_ = uuid.Nil
}
