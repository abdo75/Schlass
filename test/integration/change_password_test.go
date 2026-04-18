//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/abdo75/Schlass/internal/crypto"
	"github.com/abdo75/Schlass/internal/store"
)

// changePassword is a small helper that POSTs /api/change-password with the
// given cookie and returns the raw response recorder. Kept inline (not on
// TestEnv) because it's only used here.
func changePassword(t *testing.T, env *TestEnv, cookie *http.Cookie, current, next string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{
		"current_password": current,
		"new_password":     next,
	})
	if err != nil {
		t.Fatalf("marshal change-password body: %v", err)
	}
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/change-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	return rec
}

// getMe issues GET /api/me using the given cookie and returns the recorder.
func getMe(t *testing.T, env *TestEnv, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), "GET", "/api/me", nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	return rec
}

// sessionCookie extracts the schlass_session cookie from a recorder, if any.
func sessionCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == "schlass_session" {
			return c
		}
	}
	return nil
}

// TestChangePassword_RotatesSessionToken is the load-bearing test for the
// OWASP-aligned session rotation contract: after a successful password
// change, the old session token must be revoked and the cookie must point at
// a fresh, different token that authenticates the same user.
func TestChangePassword_RotatesSessionToken(t *testing.T) {
	env := setupIntegrationEnv(t)
	defer env.Cleanup()

	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")
	oldCookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse42!")

	rec := changePassword(t, env, oldCookie, "CorrectHorse42!", "NewPasscode99!")
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}

	newCookie := sessionCookie(rec)
	if newCookie == nil {
		t.Fatal("no schlass_session cookie set on rotation response")
	}
	if newCookie.Value == oldCookie.Value {
		t.Fatal("session token was not rotated: new value matches old value")
	}
	if !newCookie.HttpOnly || newCookie.SameSite != http.SameSiteStrictMode || newCookie.Path != "/" {
		t.Fatalf("rotated cookie has wrong attributes: %+v", newCookie)
	}

	// Old token must no longer authenticate.
	if rec := getMe(t, env, oldCookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("old token still valid after rotation: got %d", rec.Code)
	}
	// New token must authenticate the same user.
	meRec := getMe(t, env, newCookie)
	if meRec.Code != http.StatusOK {
		t.Fatalf("new token not accepted: %d %s", meRec.Code, meRec.Body.String())
	}
	var meBody struct {
		User struct {
			Email               string `json:"email"`
			ForcePasswordChange bool   `json:"force_password_change"`
		} `json:"user"`
	}
	if err := json.NewDecoder(strings.NewReader(meRec.Body.String())).Decode(&meBody); err != nil {
		t.Fatalf("decode /api/me body: %v", err)
	}
	if meBody.User.Email != "admin@example.com" {
		t.Fatalf("rotated session authenticates wrong user: %q", meBody.User.Email)
	}
	if meBody.User.ForcePasswordChange {
		t.Fatal("force_password_change should be false after self-service change")
	}

	// And the new password must be accepted by /api/login.
	body := bytes.NewBufferString(`{"email":"admin@example.com","password":"NewPasscode99!"}`)
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/login", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://localhost:3000")
	loginRec := httptest.NewRecorder()
	env.Router.ServeHTTP(loginRec, req)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login with new password: want 200, got %d %s", loginRec.Code, loginRec.Body.String())
	}
}

// TestChangePassword_WrongCurrentPassword asserts that a bad current_password
// returns 400 WRONG_CURRENT_PASSWORD and leaves the existing session intact.
func TestChangePassword_WrongCurrentPassword(t *testing.T) {
	env := setupIntegrationEnv(t)
	defer env.Cleanup()

	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")
	cookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse42!")

	rec := changePassword(t, env, cookie, "DefinitelyWrong!", "NewPasscode99!")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "WRONG_CURRENT_PASSWORD") {
		t.Fatalf("want WRONG_CURRENT_PASSWORD, got %s", rec.Body.String())
	}
	if sessionCookie(rec) != nil {
		t.Fatal("session cookie should not be rotated on wrong current password")
	}

	// Existing session must still work.
	meRec := getMe(t, env, cookie)
	if meRec.Code != http.StatusOK {
		t.Fatalf("session unexpectedly invalidated: %d %s", meRec.Code, meRec.Body.String())
	}
}

// TestChangePassword_WeakNewPassword asserts that a new password that
// violates policy returns 400 PASSWORD_POLICY_VIOLATION and does not touch
// the session.
func TestChangePassword_WeakNewPassword(t *testing.T) {
	env := setupIntegrationEnv(t)
	defer env.Cleanup()

	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")
	cookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse42!")

	rec := changePassword(t, env, cookie, "CorrectHorse42!", "short")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "PASSWORD_POLICY_VIOLATION") {
		t.Fatalf("want PASSWORD_POLICY_VIOLATION, got %s", rec.Body.String())
	}
	if sessionCookie(rec) != nil {
		t.Fatal("session cookie should not be rotated on policy violation")
	}

	meRec := getMe(t, env, cookie)
	if meRec.Code != http.StatusOK {
		t.Fatalf("session unexpectedly invalidated: %d %s", meRec.Code, meRec.Body.String())
	}
}

// TestChangePassword_FromForcedFlow simulates the admin-reset → forced-change
// flow: a user is created with force_password_change=true, logs in with the
// temp password, sees /api/me report the forced flag, then self-changes —
// after which /api/me must report force_password_change=false.
func TestChangePassword_FromForcedFlow(t *testing.T) {
	env := setupIntegrationEnv(t)
	defer env.Cleanup()

	// Seed directly via UserStore with force_password_change=true (bypasses
	// SeedAdmin so we can control the flag).
	tempPw := "TempPass4Now!"
	hash, err := crypto.HashPassword(tempPw)
	if err != nil {
		t.Fatalf("hash temp password: %v", err)
	}
	us := store.NewUserStore()
	if _, err := us.Create(context.Background(), env.Pool, "user@example.com", hash, "super_admin", true); err != nil {
		t.Fatalf("seed forced user: %v", err)
	}

	cookie := env.LoginAsAdmin(t, "user@example.com", tempPw)

	// /api/me should report force_password_change=true.
	meRec := getMe(t, env, cookie)
	if meRec.Code != http.StatusOK {
		t.Fatalf("GET /api/me: %d %s", meRec.Code, meRec.Body.String())
	}
	var meBefore struct {
		User struct {
			ForcePasswordChange bool `json:"force_password_change"`
		} `json:"user"`
	}
	if err := json.NewDecoder(strings.NewReader(meRec.Body.String())).Decode(&meBefore); err != nil {
		t.Fatalf("decode /api/me body: %v", err)
	}
	if !meBefore.User.ForcePasswordChange {
		t.Fatal("expected force_password_change=true before change")
	}

	// Self-change.
	rec := changePassword(t, env, cookie, tempPw, "RealPassword55!")
	if rec.Code != http.StatusOK {
		t.Fatalf("change-password: want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	newCookie := sessionCookie(rec)
	if newCookie == nil {
		t.Fatal("no rotated cookie after forced-flow change")
	}

	// /api/me on the rotated cookie must now report force_password_change=false.
	meRec2 := getMe(t, env, newCookie)
	if meRec2.Code != http.StatusOK {
		t.Fatalf("GET /api/me after change: %d %s", meRec2.Code, meRec2.Body.String())
	}
	var meAfter struct {
		User struct {
			ForcePasswordChange bool `json:"force_password_change"`
		} `json:"user"`
	}
	if err := json.NewDecoder(strings.NewReader(meRec2.Body.String())).Decode(&meAfter); err != nil {
		t.Fatalf("decode /api/me body: %v", err)
	}
	if meAfter.User.ForcePasswordChange {
		t.Fatal("expected force_password_change=false after self-service change")
	}
}
