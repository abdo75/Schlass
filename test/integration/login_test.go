//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLogin_IssuesSessionCookieOnCorrectCredentials(t *testing.T) {
	env := setupIntegrationEnv(t)
	defer env.Cleanup()

	// Seed an admin user via the setup wizard (or direct store call)
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")

	// Disable MFA so this test exercises the legacy 200-path.
	if _, err := env.Pool.Exec(t.Context(), `UPDATE instance_config SET value = 'false' WHERE key = 'mfa_required'`); err != nil {
		t.Fatalf("disable mfa: %v", err)
	}

	body := bytes.NewBufferString(`{"email":"admin@example.com","password":"CorrectHorse42!"}`)
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/login", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://localhost:3000")

	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}

	cookies := rec.Result().Cookies()
	var sess *http.Cookie
	for _, c := range cookies {
		if c.Name == "schlass_session" {
			sess = c
			break
		}
	}
	if sess == nil {
		t.Fatal("no schlass_session cookie set")
	}
	if !sess.HttpOnly {
		t.Fatal("cookie must be HttpOnly")
	}
	if sess.SameSite != http.SameSiteStrictMode {
		t.Fatal("cookie must be SameSite=Strict")
	}
	if sess.Path != "/" {
		t.Fatalf("cookie path: %q", sess.Path)
	}

	var respBody struct {
		User struct {
			ID                  string `json:"id"`
			Email               string `json:"email"`
			Role                string `json:"role"`
			ForcePasswordChange bool   `json:"force_password_change"`
		} `json:"user"`
	}
	if err := json.NewDecoder(strings.NewReader(rec.Body.String())).Decode(&respBody); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if respBody.User.Email != "admin@example.com" {
		t.Fatalf("user email: %q", respBody.User.Email)
	}
	if respBody.User.Role != "super_admin" {
		t.Fatalf("user role: %q", respBody.User.Role)
	}
}

func TestLogin_WrongPassword_IncrementsCounter(t *testing.T) {
	env := setupIntegrationEnv(t)
	defer env.Cleanup()
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")

	body := bytes.NewBufferString(`{"email":"admin@example.com","password":"wrong"}`)
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/login", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)

	if rec.Code != 401 {
		t.Fatalf("want 401, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "INVALID_CREDENTIALS") {
		t.Fatalf("want INVALID_CREDENTIALS, got %s", rec.Body.String())
	}

	// Verify counter incremented in DB
	var count int
	if err := env.Pool.QueryRow(context.Background(),
		"SELECT failed_login_attempts FROM users WHERE email=$1",
		"admin@example.com").Scan(&count); err != nil {
		t.Fatalf("scan counter: %v", err)
	}
	if count != 1 {
		t.Fatalf("counter not incremented: got %d", count)
	}
}

func TestLogin_LockoutCycle(t *testing.T) {
	env := setupIntegrationEnv(t)
	defer env.Cleanup()
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")

	attempt := func(pw string) *httptest.ResponseRecorder {
		body := bytes.NewBufferString(`{"email":"admin@example.com","password":"` + pw + `"}`)
		req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/login", body)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "http://localhost:3000")
		rec := httptest.NewRecorder()
		env.Router.ServeHTTP(rec, req)
		return rec
	}

	// 5 wrong attempts (threshold default is 5)
	for i := 0; i < 5; i++ {
		rec := attempt("wrong")
		if rec.Code != 401 {
			t.Fatalf("attempt %d: want 401, got %d", i, rec.Code)
		}
	}

	// 6th attempt with CORRECT password must still return ACCOUNT_LOCKED
	rec := attempt("CorrectHorse42!")
	if rec.Code != 401 {
		t.Fatalf("locked correct attempt: want 401, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "ACCOUNT_LOCKED") {
		t.Fatalf("want ACCOUNT_LOCKED, got %s", rec.Body.String())
	}

	// Fast-forward: directly update locked_until to the past
	_, err := env.Pool.Exec(context.Background(),
		`UPDATE users SET locked_until = now() - interval '10 seconds' WHERE email=$1`,
		"admin@example.com")
	if err != nil {
		t.Fatalf("fast-forward update: %v", err)
	}

	// Disable MFA so the post-lockout attempt takes the legacy 200-path.
	if _, err := env.Pool.Exec(context.Background(), `UPDATE instance_config SET value = 'false' WHERE key = 'mfa_required'`); err != nil {
		t.Fatalf("disable mfa: %v", err)
	}

	// Correct attempt succeeds and resets counter
	rec = attempt("CorrectHorse42!")
	if rec.Code != 200 {
		t.Fatalf("post-lockout correct: want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var count int
	if err := env.Pool.QueryRow(context.Background(),
		"SELECT failed_login_attempts FROM users WHERE email=$1",
		"admin@example.com").Scan(&count); err != nil {
		t.Fatalf("scan counter: %v", err)
	}
	if count != 0 {
		t.Fatalf("counter not reset: got %d", count)
	}
}

func TestLogin_OriginCheck(t *testing.T) {
	env := setupIntegrationEnv(t)
	defer env.Cleanup()
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")

	// Disable MFA so the correct-origin attempt takes the legacy 200-path.
	if _, err := env.Pool.Exec(t.Context(), `UPDATE instance_config SET value = 'false' WHERE key = 'mfa_required'`); err != nil {
		t.Fatalf("disable mfa: %v", err)
	}

	doWithOrigin := func(origin string) int {
		body := bytes.NewBufferString(`{"email":"admin@example.com","password":"CorrectHorse42!"}`)
		req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/login", body)
		req.Header.Set("Content-Type", "application/json")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		rec := httptest.NewRecorder()
		env.Router.ServeHTTP(rec, req)
		return rec.Code
	}

	if got := doWithOrigin(""); got != 403 {
		t.Fatalf("no origin: want 403, got %d", got)
	}
	if got := doWithOrigin("https://evil.example"); got != 403 {
		t.Fatalf("wrong origin: want 403, got %d", got)
	}
	if got := doWithOrigin("http://localhost:3000"); got != 200 {
		t.Fatalf("correct origin: want 200, got %d", got)
	}
}

func TestLogin_EnumerationDefense(t *testing.T) {
	env := setupIntegrationEnv(t)
	defer env.Cleanup()
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")

	unknown := bytes.NewBufferString(`{"email":"nobody@example.com","password":"whatever"}`)
	knownWrong := bytes.NewBufferString(`{"email":"admin@example.com","password":"wrong"}`)

	doReq := func(body *bytes.Buffer) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/login", body)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "http://localhost:3000")
		rec := httptest.NewRecorder()
		env.Router.ServeHTTP(rec, req)
		return rec
	}

	rec1 := doReq(unknown)
	rec2 := doReq(knownWrong)

	if rec1.Code != 401 || rec2.Code != 401 {
		t.Fatalf("both want 401, got %d and %d", rec1.Code, rec2.Code)
	}
	if !strings.Contains(rec1.Body.String(), "INVALID_CREDENTIALS") {
		t.Fatalf("unknown: want INVALID_CREDENTIALS, got %s", rec1.Body.String())
	}
	if !strings.Contains(rec2.Body.String(), "INVALID_CREDENTIALS") {
		t.Fatalf("known-wrong: want INVALID_CREDENTIALS, got %s", rec2.Body.String())
	}
}

func TestLogin_PasswordNeverLogged(t *testing.T) {
	env := setupIntegrationEnv(t)
	defer env.Cleanup()
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")

	sentinel := "SENTINEL_PASSWORD_SHOULD_NEVER_APPEAR_42"

	// Capture slog output by installing a test handler on slog.Default()
	logs := env.CaptureLogs(t)

	body := bytes.NewBufferString(`{"email":"admin@example.com","password":"` + sentinel + `"}`)
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/login", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	_ = rec

	if strings.Contains(logs.String(), sentinel) {
		t.Fatalf("sentinel password appeared in logs")
	}

	// Audit metadata grep
	var match int
	if err := env.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_logs WHERE metadata::text LIKE '%' || $1 || '%'`,
		sentinel).Scan(&match); err != nil {
		t.Fatalf("scan match: %v", err)
	}
	if match != 0 {
		t.Fatalf("sentinel appeared in %d audit rows", match)
	}
}

// Spec §5.2 test 7 — audit trail completeness
func TestLogin_AuditTrailCompleteness(t *testing.T) {
	env := setupIntegrationEnv(t)
	defer env.Cleanup()
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")

	for i := 0; i < 5; i++ {
		body := bytes.NewBufferString(`{"email":"admin@example.com","password":"wrong"}`)
		req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/login", body)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "http://localhost:3000")
		rec := httptest.NewRecorder()
		env.Router.ServeHTTP(rec, req)
		_ = rec
	}

	var failedCount, lockedCount int
	if err := env.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_logs WHERE event_type='login.failed' AND actor_email=$1`,
		"admin@example.com").Scan(&failedCount); err != nil {
		t.Fatalf("scan failedCount: %v", err)
	}
	if failedCount != 5 {
		t.Fatalf("expected 5 login.failed rows, got %d", failedCount)
	}
	if err := env.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_logs WHERE event_type='account.locked' AND actor_email=$1`,
		"admin@example.com").Scan(&lockedCount); err != nil {
		t.Fatalf("scan lockedCount: %v", err)
	}
	if lockedCount != 1 {
		t.Fatalf("expected 1 account.locked row, got %d", lockedCount)
	}

	// Every login.failed row must have actor_id populated, non-empty ip, outcome=failure.
	// ip_address is INET — cast to text so pgx scans cleanly into a Go string.
	rows, _ := env.Pool.Query(context.Background(),
		`SELECT actor_id, ip_address::text, outcome FROM audit_logs WHERE event_type='login.failed' AND actor_email=$1`,
		"admin@example.com")
	defer rows.Close()
	for rows.Next() {
		var actorID *string
		var ip string
		var outcome string
		if err := rows.Scan(&actorID, &ip, &outcome); err != nil {
			t.Fatalf("scan audit row: %v", err)
		}
		if actorID == nil {
			t.Error("login.failed row missing actor_id")
		}
		if ip == "" {
			t.Error("login.failed row missing ip_address")
		}
		if outcome != "failure" {
			t.Errorf("login.failed row has outcome=%q", outcome)
		}
	}
}

// Spec §5.2 test 8 — audit write failure rolls back the login tx
func TestLogin_AuditFailureRollsBack(t *testing.T) {
	env := setupIntegrationEnv(t)
	defer env.Cleanup()
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")

	// Disable MFA so the correct-password path reaches login.succeeded audit
	// write (the legacy path) where the fake store will trigger the 500.
	if _, err := env.Pool.Exec(t.Context(), `UPDATE instance_config SET value = 'false' WHERE key = 'mfa_required'`); err != nil {
		t.Fatalf("disable mfa: %v", err)
	}

	// Swap in a fake audit store that always errors on Log
	env.WithFakeAuditStore(t, func() error { return errors.New("simulated audit failure") })

	body := bytes.NewBufferString(`{"email":"admin@example.com","password":"CorrectHorse42!"}`)
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/login", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)

	if rec.Code != 500 {
		t.Fatalf("want 500, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "INTERNAL_ERROR") {
		t.Fatalf("want INTERNAL_ERROR, got %s", rec.Body.String())
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "schlass_session" && c.Value != "" {
			t.Fatal("session cookie must not be set when audit write fails")
		}
	}

	// failed_login_attempts must remain 0 (tx rolled back)
	var count int
	if err := env.Pool.QueryRow(context.Background(),
		"SELECT failed_login_attempts FROM users WHERE email=$1",
		"admin@example.com").Scan(&count); err != nil {
		t.Fatalf("scan counter: %v", err)
	}
	if count != 0 {
		t.Fatalf("counter changed despite rollback: got %d", count)
	}
}

// Regression test for the concurrent-lock race fixed in Task 2's
// ResetFailedLogins WHERE clause. A correct password arriving after a
// concurrent wrong-password attempt has locked the account must respond
// ACCOUNT_LOCKED, not 200, and the lock must remain in place.
func TestLogin_CorrectPasswordWhileConcurrentlyLocked(t *testing.T) {
	env := setupIntegrationEnv(t)
	defer env.Cleanup()
	id := env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")

	// Simulate the race deterministically: set the account to locked state
	// directly in SQL, mimicking what a concurrent attacker's 5th wrong
	// attempt would have left behind between our GetByEmail snapshot and
	// our ResetFailedLogins call.
	_, _ = env.Pool.Exec(context.Background(),
		`UPDATE users SET failed_login_attempts = 5, locked_until = now() + interval '1 hour' WHERE id = $1`,
		id)

	body := bytes.NewBufferString(`{"email":"admin@example.com","password":"CorrectHorse42!"}`)
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/login", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)

	if rec.Code != 401 {
		t.Fatalf("want 401, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "ACCOUNT_LOCKED") {
		t.Fatalf("want ACCOUNT_LOCKED, got %s", rec.Body.String())
	}
	var lockedUntil *time.Time
	if err := env.Pool.QueryRow(context.Background(),
		`SELECT locked_until FROM users WHERE id=$1`, id).Scan(&lockedUntil); err != nil {
		t.Fatalf("scan locked_until: %v", err)
	}
	if lockedUntil == nil || !lockedUntil.After(time.Now()) {
		t.Fatal("lockout was silently cleared by the failed correct-attempt")
	}
}
