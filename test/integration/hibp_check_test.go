//go:build integration

package integration

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // G505: SHA-1 is the HIBP API contract.
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// hibpStubPwned returns an httptest.Server that always reports the specific
// password `pwnedPassword` as pwned (count=999), plus padding. Any other
// password returns a response that does not include the matching suffix
// (i.e. "unknown").
func hibpStubPwned(t *testing.T, pwnedPassword string) *httptest.Server {
	t.Helper()
	sum := sha1.Sum([]byte(pwnedPassword)) //nolint:gosec // G401
	full := strings.ToUpper(hex.EncodeToString(sum[:]))
	wantPrefix, wantSuffix := full[:5], full[5:]

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.URL.Path, "/")
		if strings.EqualFold(got, wantPrefix) {
			_, _ = fmt.Fprintf(w, "%s:999\r\n", wantSuffix)
			_, _ = fmt.Fprint(w, "000000000000000000000000000000AAAAA:0\r\n") // padding
			return
		}
		// Different prefix: return an unrelated entry so the suffix won't match.
		_, _ = fmt.Fprint(w, "000000000000000000000000000000BBBBB:7\r\n")
	}))
}

// hibpStubDown returns a server that always returns 500 to simulate an HIBP
// outage. Callers must fail-open: a 500 from HIBP must not block the operation.
func hibpStubDown(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
}

// TestHIBP_Setup_BreachedPassword_Rejected asserts that POST /api/setup
// returns 400 PASSWORD_BREACHED when the submitted password matches the stub's
// pwned list.
func TestHIBP_Setup_BreachedPassword_Rejected(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()

	const pw = "BreachedPass1!"
	stub := hibpStubPwned(t, pw)
	defer stub.Close()
	env.WithHIBPChecker(t, stub.URL)

	body, _ := json.Marshal(map[string]string{
		"email":            "admin@example.com",
		"password":         pw,
		"confirm_password": pw,
		"instance_name":    "Acme",
	})
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/setup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400: %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&out)
	if out["error"] != "PASSWORD_BREACHED" {
		t.Fatalf("error = %q, want PASSWORD_BREACHED", out["error"])
	}
}

// TestHIBP_Setup_FailOpenOnHIBPDown asserts that a 500 from the stub
// (simulating HIBP outage) does NOT block setup — the handler must fail-open.
func TestHIBP_Setup_FailOpenOnHIBPDown(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()

	stub := hibpStubDown(t)
	defer stub.Close()
	env.WithHIBPChecker(t, stub.URL)

	const pw = "UnbreachedPass1!"
	body, _ := json.Marshal(map[string]string{
		"email":            "admin2@example.com",
		"password":         pw,
		"confirm_password": pw,
		"instance_name":    "Acme",
	})
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/setup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200 (fail-open): %s", rec.Code, rec.Body.String())
	}
}

// TestHIBP_ChangePassword_BreachedPassword_Rejected asserts that
// POST /api/change-password returns 400 PASSWORD_BREACHED when the new
// password matches the stub's pwned list.
//
// Setup and login happen BEFORE WithHIBPChecker so the initial password
// bypasses HIBP (correct: the test harness doesn't want to gate setup).
// The session cookie remains valid after the router rebuild because sessions
// live in Valkey, which is shared across router instances.
func TestHIBP_ChangePassword_BreachedPassword_Rejected(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	env.CompleteSetup(t, "admin@example.com", "AdminPass12345!")
	cookie := env.LoginAsAdmin(t, "admin@example.com", "AdminPass12345!")

	const pw = "BreachedNewPass1!"
	stub := hibpStubPwned(t, pw)
	defer stub.Close()
	env.WithHIBPChecker(t, stub.URL)

	body, _ := json.Marshal(map[string]string{
		"current_password": "AdminPass12345!",
		"new_password":     pw,
	})
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/change-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400: %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&out)
	if out["error"] != "PASSWORD_BREACHED" {
		t.Fatalf("error = %q, want PASSWORD_BREACHED", out["error"])
	}
}

// TestHIBP_PasswordReset_BreachedPassword_Rejected asserts that
// POST /api/password-reset/confirm returns 400 PASSWORD_BREACHED when the
// submitted password matches the stub's pwned list, and also asserts that
// the reset token is NOT consumed so the user can retry with a clean password.
func TestHIBP_PasswordReset_BreachedPassword_Rejected(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	uid := env.DirectCreateUser(t, "reset-hibp@example.com", "user")

	const pw = "BreachedResetPass1!"
	stub := hibpStubPwned(t, pw)
	defer stub.Close()
	env.WithHIBPChecker(t, stub.URL)

	tok := env.InsertResetToken(t, uid, 30*time.Minute)
	body, _ := json.Marshal(map[string]any{"token": tok, "password": pw})
	resp := publicPost(t, env, "/api/password-reset/confirm", body)

	if resp.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400: %s", resp.Code, resp.Body.String())
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["error"] != "PASSWORD_BREACHED" {
		t.Fatalf("error = %q, want PASSWORD_BREACHED", out["error"])
	}

	// Token must NOT be consumed — user should be able to retry with a
	// different password.
	var usedAt *time.Time
	if err := env.Pool.QueryRow(t.Context(),
		`SELECT used_at FROM password_reset_tokens WHERE user_id = $1`, uid,
	).Scan(&usedAt); err != nil {
		t.Fatalf("query used_at: %v", err)
	}
	if usedAt != nil {
		t.Fatal("token should NOT be marked used on PASSWORD_BREACHED reject")
	}
}
