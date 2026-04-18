//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/abdo75/Schlass/internal/session"
)

// TestPostLogin_ReturnTo_NoMFA_EmitsRedirectTo covers the happy path: no
// MFA, valid /authorize return_to, handler emits redirect_to on the 200.
func TestPostLogin_ReturnTo_NoMFA_EmitsRedirectTo(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")
	if _, err := env.Pool.Exec(t.Context(), `UPDATE instance_config SET value = 'false' WHERE key = 'mfa_required'`); err != nil {
		t.Fatalf("disable mfa: %v", err)
	}

	want := "/authorize?client_id=abc&state=xyz"
	body, _ := json.Marshal(map[string]string{
		"email":     "admin@example.com",
		"password":  "CorrectHorse1Battery",
		"return_to": want,
	})
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if got := resp["redirect_to"]; got != want {
		t.Fatalf("redirect_to: got %v want %q", got, want)
	}
}

// TestPostLogin_ReturnTo_NoMFA_DropsInvalid verifies off-origin / non-authorize
// values are silently dropped, not echoed in the response.
func TestPostLogin_ReturnTo_NoMFA_DropsInvalid(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")
	if _, err := env.Pool.Exec(t.Context(), `UPDATE instance_config SET value = 'false' WHERE key = 'mfa_required'`); err != nil {
		t.Fatalf("disable mfa: %v", err)
	}

	for _, bad := range []string{
		"https://evil.example.com/authorize",
		"/account",
		"//evil.example.com/authorize",
		"javascript:alert(1)",
	} {
		t.Run(bad, func(t *testing.T) {
			body, _ := json.Marshal(map[string]string{
				"email":     "admin@example.com",
				"password":  "CorrectHorse1Battery",
				"return_to": bad,
			})
			req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/login", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", "http://localhost:3000")
			rec := httptest.NewRecorder()
			env.Router.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
			}
			var resp map[string]any
			_ = json.Unmarshal(rec.Body.Bytes(), &resp)
			if _, present := resp["redirect_to"]; present {
				t.Fatalf("invalid return_to leaked into redirect_to: %v", resp["redirect_to"])
			}
		})
	}
}

// TestPostLogin_ReturnTo_ForcePasswordChange_StampsSession covers the force-PW
// branch: session is issued via CreateWithPendingReturnTo, so the stashed
// return_to is retrievable by inspecting the session hydrated from Valkey.
func TestPostLogin_ReturnTo_ForcePasswordChange_StampsSession(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")

	if _, err := env.Pool.Exec(t.Context(), `UPDATE instance_config SET value = 'false' WHERE key = 'mfa_required'`); err != nil {
		t.Fatalf("disable mfa: %v", err)
	}
	adminCookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse1Battery")

	createBody, _ := json.Marshal(map[string]string{"email": "newuser@example.com", "role": "user"})
	createReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/users", bytes.NewReader(createBody))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("Origin", "http://localhost:3000")
	createReq.AddCookie(adminCookie)
	createRec := httptest.NewRecorder()
	env.Router.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create user: %d %s", createRec.Code, createRec.Body.String())
	}
	var createResp struct {
		TemporaryPassword string `json:"temporary_password"`
	}
	if err := json.NewDecoder(createRec.Body).Decode(&createResp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	want := "/authorize?client_id=abc&state=xyz"
	loginBody, _ := json.Marshal(map[string]string{
		"email":     "newuser@example.com",
		"password":  createResp.TemporaryPassword,
		"return_to": want,
	})
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/login", bytes.NewReader(loginBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login: %d %s", rec.Code, rec.Body.String())
	}

	// The force-PW response deliberately does NOT echo redirect_to — the SPA
	// must first complete password rotation. The return_to surfaces on the
	// subsequent /api/change-password success.
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if _, present := resp["redirect_to"]; present {
		t.Fatal("force-PW login must not emit redirect_to yet")
	}

	var sessionCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "schlass_session" {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatal("no session cookie")
	}

	store := session.NewValkeyStore(env.ValkeyClient, 24*3600*1_000_000_000)
	got, err := store.Get(t.Context(), sessionCookie.Value)
	if err != nil {
		t.Fatalf("session Get: %v", err)
	}
	if got.PendingReturnTo != want {
		t.Fatalf("PendingReturnTo: got %q want %q", got.PendingReturnTo, want)
	}
}

// TestPostLogin_ReturnTo_MfaEnroll_StashesInValkey covers the enrollment branch:
// return_to is HSet into the mfa:enroll:<token> hash alongside user_id.
func TestPostLogin_ReturnTo_MfaEnroll_StashesInValkey(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")

	want := "/authorize?client_id=abc&state=xyz"
	body, _ := json.Marshal(map[string]string{
		"email":     "admin@example.com",
		"password":  "CorrectHorse1Battery",
		"return_to": want,
	})
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d: %s", rec.Code, rec.Body.String())
	}
	var enrollCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "schlass_mfa_enroll" {
			enrollCookie = c
		}
	}
	if enrollCookie == nil || enrollCookie.Value == "" {
		t.Fatal("no enrollment cookie")
	}
	stored, err := env.ValkeyClient.HGet(t.Context(), "mfa:enroll:"+enrollCookie.Value, "return_to").Result()
	if err != nil {
		t.Fatalf("HGet return_to: %v", err)
	}
	if stored != want {
		t.Fatalf("stashed return_to: got %q want %q", stored, want)
	}
}

// TestPostChangePassword_ReturnTo_ForcedFlow_EmitsRedirectTo proves that a
// return_to threaded through the force_password_change login (stamped on
// the session as PendingReturnTo) surfaces in the /api/change-password
// terminal success.
func TestPostChangePassword_ReturnTo_ForcedFlow_EmitsRedirectTo(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")

	if _, err := env.Pool.Exec(t.Context(), `UPDATE instance_config SET value = 'false' WHERE key = 'mfa_required'`); err != nil {
		t.Fatalf("disable mfa: %v", err)
	}
	adminCookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse1Battery")

	createBody, _ := json.Marshal(map[string]string{"email": "newuser@example.com", "role": "user"})
	createReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/users", bytes.NewReader(createBody))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("Origin", "http://localhost:3000")
	createReq.AddCookie(adminCookie)
	createRec := httptest.NewRecorder()
	env.Router.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create user: %d %s", createRec.Code, createRec.Body.String())
	}
	var createResp struct {
		TemporaryPassword string `json:"temporary_password"`
	}
	_ = json.NewDecoder(createRec.Body).Decode(&createResp)

	want := "/authorize?client_id=abc&state=xyz"
	loginBody, _ := json.Marshal(map[string]string{
		"email":     "newuser@example.com",
		"password":  createResp.TemporaryPassword,
		"return_to": want,
	})
	loginReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/login", bytes.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginReq.Header.Set("Origin", "http://localhost:3000")
	loginRec := httptest.NewRecorder()
	env.Router.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login: %d %s", loginRec.Code, loginRec.Body.String())
	}
	var sessionCookie *http.Cookie
	for _, c := range loginRec.Result().Cookies() {
		if c.Name == "schlass_session" {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatal("no session cookie from login")
	}

	chBody, _ := json.Marshal(map[string]string{
		"current_password": createResp.TemporaryPassword,
		"new_password":     "RealPass4Now!",
	})
	chReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/change-password", bytes.NewReader(chBody))
	chReq.Header.Set("Content-Type", "application/json")
	chReq.AddCookie(sessionCookie)
	chRec := httptest.NewRecorder()
	env.Router.ServeHTTP(chRec, chReq)
	if chRec.Code != http.StatusOK {
		t.Fatalf("change-password: %d %s", chRec.Code, chRec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(chRec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode change-password body: %v", err)
	}
	if got := resp["redirect_to"]; got != want {
		t.Fatalf("redirect_to: got %v want %q", got, want)
	}
}

// TestPostChangePassword_NoReturnTo_OmitsRedirectTo verifies a plain
// self-service change-password (no OIDC context) returns a 200 with an
// empty JSON body, not a redirect_to key.
func TestPostChangePassword_NoReturnTo_OmitsRedirectTo(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")
	cookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse42!")

	body, _ := json.Marshal(map[string]string{
		"current_password": "CorrectHorse42!",
		"new_password":     "NewPasscode99!",
	})
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/change-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, present := resp["redirect_to"]; present {
		t.Fatalf("unexpected redirect_to in plain change-password: %v", resp["redirect_to"])
	}
}

// TestPostLogin_ReturnTo_MfaChallenge_StashesInValkey covers the challenge
// branch: return_to is HSet into the mfa:challenge:<token> hash.
func TestPostLogin_ReturnTo_MfaChallenge_StashesInValkey(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	enrollTestUser(t, env, "admin@example.com", "CorrectHorse1Battery")

	want := "/authorize?client_id=abc&state=xyz"
	body, _ := json.Marshal(map[string]string{
		"email":     "admin@example.com",
		"password":  "CorrectHorse1Battery",
		"return_to": want,
	})
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d: %s", rec.Code, rec.Body.String())
	}
	var challengeCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "schlass_mfa_challenge" {
			challengeCookie = c
		}
	}
	if challengeCookie == nil || challengeCookie.Value == "" {
		t.Fatal("no challenge cookie")
	}
	stored, err := env.ValkeyClient.HGet(t.Context(), "mfa:challenge:"+challengeCookie.Value, "return_to").Result()
	if err != nil {
		t.Fatalf("HGet return_to: %v", err)
	}
	if stored != want {
		t.Fatalf("stashed return_to: got %q want %q", stored, want)
	}
}
