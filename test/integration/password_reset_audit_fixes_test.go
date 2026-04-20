//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/abdo75/Schlass/internal/store"
)

// TestPasswordResetRequest_DisabledUser_NoToken (H5) — disabled user,
// 200 response (enumeration-safe), no token row created.
func TestPasswordResetRequest_DisabledUser_NoToken(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	uid := env.DirectCreateUser(t, "disabled@example.com", "user")
	if _, err := env.Pool.Exec(t.Context(),
		`UPDATE users SET status = 'disabled' WHERE id = $1`, uid,
	); err != nil {
		t.Fatalf("disable: %v", err)
	}
	body, _ := json.Marshal(map[string]any{"email": "disabled@example.com"})
	if r := publicPost(t, env, "/api/password-reset/request", body); r.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", r.Code)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var count int
	if err := env.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM password_reset_tokens WHERE user_id = $1`, uid,
	).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatalf("disabled user received %d tokens, want 0", count)
	}

	// The audit row should reflect an unmatched path (email_matched=false)
	// since disabled/non-active falls through to the enumeration-safe branch.
	var matched bool
	if err := env.Pool.QueryRow(ctx,
		`SELECT (metadata->>'email_matched')::bool
		 FROM audit_logs
		 WHERE event_type = 'password_reset.requested'
		 ORDER BY created_at DESC LIMIT 1`,
	).Scan(&matched); err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if matched {
		t.Fatal("disabled user must be audited as email_matched=false")
	}
}

// TestPasswordResetRequest_PriorTokensInvalidated (H1).
func TestPasswordResetRequest_PriorTokensInvalidated(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()

	uid := env.DirectCreateUser(t, "cycle@example.com", "user")
	ts := store.NewPasswordResetTokenStore()

	var raw [32]byte
	_, _ = rand.Read(raw[:])
	prior := base64.RawURLEncoding.EncodeToString(raw[:])
	if _, err := ts.Insert(t.Context(), env.Pool, uid, prior, 30*time.Minute, netip.Addr{}); err != nil {
		t.Fatalf("seed prior: %v", err)
	}

	body, _ := json.Marshal(map[string]any{"email": "cycle@example.com"})
	if r := publicPost(t, env, "/api/password-reset/request", body); r.Code != http.StatusOK {
		t.Fatalf("got %d", r.Code)
	}

	prev, err := ts.GetByToken(t.Context(), env.Pool, prior)
	if err != nil {
		t.Fatalf("get prior: %v", err)
	}
	if prev.UsedAt == nil {
		t.Fatal("prior token should be invalidated after a new /request")
	}

	var total int
	if err := env.Pool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM password_reset_tokens WHERE user_id = $1`, uid,
	).Scan(&total); err != nil {
		t.Fatalf("count: %v", err)
	}
	if total != 2 {
		t.Fatalf("token rows = %d, want 2 (old used + new unused)", total)
	}
}

// TestPasswordResetConfirm_ClearsLockout asserts H4: a successful
// self-reset clears failed_login_attempts + locked_until.
func TestPasswordResetConfirm_ClearsLockout(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()

	uid := env.DirectCreateUser(t, "locked@example.com", "user")
	if _, err := env.Pool.Exec(t.Context(), `
		UPDATE users
		SET failed_login_attempts = 5,
		    locked_until = now() + interval '15 minutes'
		WHERE id = $1
	`, uid); err != nil {
		t.Fatalf("seed lockout: %v", err)
	}

	tok := env.InsertResetToken(t, uid, 30*time.Minute)
	body, _ := json.Marshal(map[string]any{"token": tok, "password": "NewStrongPass1!"})
	if r := publicPost(t, env, "/api/password-reset/confirm", body); r.Code != http.StatusOK {
		t.Fatalf("confirm: %d %s", r.Code, r.Body.String())
	}

	var attempts int
	var lockedUntil *time.Time
	if err := env.Pool.QueryRow(t.Context(),
		`SELECT failed_login_attempts, locked_until FROM users WHERE id = $1`, uid,
	).Scan(&attempts, &lockedUntil); err != nil {
		t.Fatalf("query: %v", err)
	}
	if attempts != 0 {
		t.Fatalf("failed_login_attempts = %d, want 0", attempts)
	}
	if lockedUntil != nil {
		t.Fatalf("locked_until = %v, want NULL", lockedUntil)
	}
}

// TestPasswordResetRequest_EnumerationTimingParity (C1) — crude p50
// sanity check; catches the regression where one path skips Argon2id
// entirely. Not a statistical oracle.
func TestPasswordResetRequest_EnumerationTimingParity(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	env.DirectCreateUser(t, "existing@example.com", "user")

	const n = 5
	measure := func(email string) time.Duration {
		start := time.Now()
		body, _ := json.Marshal(map[string]any{"email": email})
		_ = publicPost(t, env, "/api/password-reset/request", body)
		return time.Since(start)
	}
	var matchedSum, unknownSum time.Duration
	for i := 0; i < n; i++ {
		matchedSum += measure("existing@example.com")
		unknownSum += measure("unknown@example.com")
	}
	// Guard against regressions where one path skips Argon2id entirely.
	// If either branch is 2× faster than the other, something is wrong.
	if matchedSum*2 < unknownSum {
		t.Fatalf("matched path suspiciously faster: matched=%v unknown=%v", matchedSum, unknownSum)
	}
	if unknownSum*2 < matchedSum {
		t.Fatalf("unknown path suspiciously faster: matched=%v unknown=%v", matchedSum, unknownSum)
	}
}
