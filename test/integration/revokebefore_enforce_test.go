//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// fullOIDCFlow completes a full /authorize → /token flow and returns
// (clientID, accessToken, refreshToken). The client secret is always "s".
// offline_access is always requested so a refresh_token is returned.
func fullOIDCFlow(t *testing.T, env *TestEnv, adminCookie *http.Cookie) (clientID, accessToken, refreshToken string) {
	t.Helper()
	bootstrapKey(t, env)

	const redirect = "https://rp.example.com/cb"
	clientID = seedTokenClient(t, env, redirect, []string{"openid", "profile", "email", "offline_access"})
	verifier, challenge := pkceParams()
	code := runAuthorizeAndGetCode(t, env, adminCookie, clientID, redirect, "openid profile email offline_access", verifier, challenge)

	params := buildTokenParams(clientID, code, redirect, verifier)
	rec := doTokenRequest(t, env, params)
	if rec.Code != http.StatusOK {
		t.Fatalf("fullOIDCFlow: token exchange status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("fullOIDCFlow: decode token response: %v", err)
	}
	at, _ := resp["access_token"].(string)
	rt, _ := resp["refresh_token"].(string)
	if at == "" {
		t.Fatal("fullOIDCFlow: missing access_token")
	}
	if rt == "" {
		t.Fatal("fullOIDCFlow: missing refresh_token")
	}
	return clientID, at, rt
}

// assertUserInfoStatus calls GET /userinfo with the given token and checks the status.
func assertUserInfoStatus(t *testing.T, env *TestEnv, token string, wantStatus int) {
	t.Helper()
	rec := doUserInfoRequest(t, env, token)
	if rec.Code != wantStatus {
		t.Fatalf("userinfo: want %d, got %d body=%s", wantStatus, rec.Code, rec.Body.String())
	}
}

// assertRefreshStatus fires a refresh and checks the status.
func assertRefreshStatus(t *testing.T, env *TestEnv, clientID, refreshToken string, wantStatus int) {
	t.Helper()
	rec := doRefreshRequest(t, env, clientID, "s", refreshToken)
	if rec.Code != wantStatus {
		t.Fatalf("refresh: want %d, got %d body=%s", wantStatus, rec.Code, rec.Body.String())
	}
}

// TestRevokeBefore_RefreshTokenRejectedAfterMFAReset does a full auth flow,
// then admin-resets the user's MFA (user stays active so the revoke_before
// path is exercised, not the user_disabled path), and asserts the refresh is
// rejected with 400 invalid_grant and a user.revoke_before_enforced audit row
// is written.
func TestRevokeBefore_RefreshTokenRejectedAfterMFAReset(t *testing.T) {
	env := NewTestEnv(t)

	// Enroll MFA for the actor so we can reset it later.
	actorIDStr, _ := enrollTestUser(t, env, "actor@example.com", "CorrectHorse1Battery")
	actorCookie := env.LoginAsAdmin(t, "actor@example.com", "CorrectHorse1Battery")
	actorID := env.GetUserIDByEmail(t, "actor@example.com")

	clientID, _, refreshTok := fullOIDCFlow(t, env, actorCookie)

	// Second admin resets the actor's MFA (actor stays active — only the
	// revoke_before cutoff advances, not the user status).
	secondAdminID := env.DirectCreateUser(t, "admin2@example.com", "super_admin")
	secondAdminCookie := env.DirectCreateSession(t, secondAdminID)
	_ = actorIDStr

	resetRec := adminResetMFA(t, env, secondAdminCookie, actorID.String())
	if resetRec.Code != http.StatusOK {
		t.Fatalf("reset-mfa: want 200, got %d: %s", resetRec.Code, resetRec.Body.String())
	}

	// Attempt refresh: should be 400 invalid_grant (revoke_before enforced).
	refreshRec := doRefreshRequest(t, env, clientID, "s", refreshTok)
	if refreshRec.Code != http.StatusBadRequest {
		t.Fatalf("refresh after mfa-reset: want 400, got %d body=%s", refreshRec.Code, refreshRec.Body.String())
	}
	var body map[string]string
	_ = json.NewDecoder(refreshRec.Body).Decode(&body)
	if got := body["error"]; got != "invalid_grant" {
		t.Fatalf("refresh error: want invalid_grant, got %q", got)
	}

	// user.revoke_before_enforced audit row should exist.
	var evType string
	err := env.Pool.QueryRow(context.Background(),
		`SELECT event_type FROM audit_logs
		 WHERE event_type = 'user.revoke_before_enforced'
		   AND actor_id = $1
		 ORDER BY created_at DESC LIMIT 1`,
		actorID,
	).Scan(&evType)
	if err != nil {
		t.Fatalf("user.revoke_before_enforced audit row missing: %v", err)
	}
}

// TestRevokeBefore_UserInfoRejectedAfterPasswordReset does a full auth flow,
// resets the user's password as admin, then verifies the old access token is
// rejected with 401 invalid_token.
func TestRevokeBefore_UserInfoRejectedAfterPasswordReset(t *testing.T) {
	env := NewTestEnv(t)

	actorID := env.SeedAdmin(t, "actor@example.com", "CorrectHorse42!")
	actorCookie := env.LoginAsAdmin(t, "actor@example.com", "CorrectHorse42!")

	_, accessTok, _ := fullOIDCFlow(t, env, actorCookie)

	// Second admin performs the password reset.
	secondAdminID := env.DirectCreateUser(t, "admin2@example.com", "super_admin")
	secondAdminCookie := env.DirectCreateSession(t, secondAdminID)

	resetRec := adminResetPassword(t, env, secondAdminCookie, actorID.String())
	if resetRec.Code != http.StatusOK {
		t.Fatalf("reset-password: want 200, got %d: %s", resetRec.Code, resetRec.Body.String())
	}

	// Old access token should now be rejected at /userinfo.
	uiRec := doUserInfoRequest(t, env, accessTok)
	if uiRec.Code != http.StatusUnauthorized {
		t.Fatalf("userinfo with stale token: want 401, got %d body=%s", uiRec.Code, uiRec.Body.String())
	}
	wwwAuth := uiRec.Header().Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, "invalid_token") {
		t.Fatalf("WWW-Authenticate should mention invalid_token, got %q", wwwAuth)
	}
}

// TestRevokeBefore_AccessTokensIssuedAfterCutoffAreAccepted does two full auth
// flows. After the first, a mutation advances the cutoff. The second flow
// produces tokens whose iat > cutoff — those should be accepted.
func TestRevokeBefore_AccessTokensIssuedAfterCutoffAreAccepted(t *testing.T) {
	env := NewTestEnv(t)

	actorID := env.SeedAdmin(t, "actor@example.com", "CorrectHorse42!")
	actorCookie := env.LoginAsAdmin(t, "actor@example.com", "CorrectHorse42!")

	// First flow — tokens issued before mutation.
	_, _, _ = fullOIDCFlow(t, env, actorCookie)

	// Second admin performs password reset (advances revoke_before).
	secondAdminID := env.DirectCreateUser(t, "admin2@example.com", "super_admin")
	secondAdminCookie := env.DirectCreateSession(t, secondAdminID)
	resetRec := adminResetPassword(t, env, secondAdminCookie, actorID.String())
	if resetRec.Code != http.StatusOK {
		t.Fatalf("reset-password: want 200, got %d", resetRec.Code)
	}

	// revoke_before is stored at second resolution; SetNow rounds the cutoff
	// up to the next whole second, so a fresh token must be issued *at or
	// after* that next-second boundary to be accepted. In real usage the
	// delay between admin mutation and user re-login is multi-second; this
	// sleep simulates that boundary deterministically for the test.
	time.Sleep(1100 * time.Millisecond)

	// Log in again with the new temp password to get a fresh session.
	var tempPwd string
	var resetResp map[string]string
	_ = json.NewDecoder(resetRec.Body).Decode(&resetResp)
	tempPwd = resetResp["temporary_password"]
	if tempPwd == "" {
		t.Fatal("no temporary_password in reset response")
	}

	// Disable MFA so the login works without an MFA challenge.
	if _, err := env.Pool.Exec(context.Background(), `UPDATE instance_config SET value = 'false' WHERE key = 'mfa_required'`); err != nil {
		t.Fatalf("disable mfa: %v", err)
	}

	// Login with temp password — actor has force_password_change=true, so they
	// get a session but are redirected to /change-password. That's fine for our
	// purposes; we just need an active session to drive /authorize.
	loginBody := strings.NewReader(`{"email":"actor@example.com","password":"` + tempPwd + `"}`)
	loginReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/login", loginBody)
	loginReq.Header.Set("Content-Type", "application/json")
	loginReq.Header.Set("Origin", "http://localhost:3000")
	loginRec := httptest.NewRecorder()
	env.Router.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login with temp pwd: want 200, got %d body=%s", loginRec.Code, loginRec.Body.String())
	}
	var freshCookie *http.Cookie
	for _, c := range loginRec.Result().Cookies() {
		if c.Name == "schlass_session" {
			freshCookie = c
		}
	}
	if freshCookie == nil {
		t.Fatal("no session cookie after temp-pwd login")
	}

	// Need to clear force_password_change so /authorize works.
	if _, err := env.Pool.Exec(context.Background(),
		`UPDATE users SET force_password_change = false WHERE id = $1`, actorID,
	); err != nil {
		t.Fatalf("clear force_password_change: %v", err)
	}

	// Run a second full OIDC flow — new tokens issued after the cutoff.
	const redirect = "https://rp.example.com/cb"
	clientID := seedTokenClient(t, env, redirect, []string{"openid", "profile", "offline_access"})
	verifier, challenge := pkceParams()
	code2 := runAuthorizeAndGetCode(t, env, freshCookie, clientID, redirect, "openid profile offline_access", verifier, challenge)
	params2 := buildTokenParams(clientID, code2, redirect, verifier)
	rec2 := doTokenRequest(t, env, params2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("second token exchange: got %d body=%s", rec2.Code, rec2.Body.String())
	}
	var resp2 map[string]any
	_ = json.NewDecoder(rec2.Body).Decode(&resp2)
	at2, _ := resp2["access_token"].(string)
	rt2, _ := resp2["refresh_token"].(string)

	// access_2: /userinfo should 200.
	assertUserInfoStatus(t, env, at2, http.StatusOK)

	// refresh_2: /token should 200.
	assertRefreshStatus(t, env, clientID, rt2, http.StatusOK)
}

// TestRevokeBefore_UnsetAllowsAllTokens creates a brand-new user with no
// mutations, performs an OIDC flow, and asserts both /userinfo and /token
// refresh work normally (no revoke_before key in Valkey).
func TestRevokeBefore_UnsetAllowsAllTokens(t *testing.T) {
	env := NewTestEnv(t)

	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")
	adminCookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse42!")

	clientID, accessTok, refreshTok := fullOIDCFlow(t, env, adminCookie)

	// Confirm no revoke_before key exists in Valkey.
	adminID := env.GetUserIDByEmail(t, "admin@example.com")
	_, err := env.ValkeyClient.Get(context.Background(), "user:revoke_before:"+adminID.String()).Result()
	if err == nil {
		t.Fatal("expected no revoke_before key for unmodified user")
	}

	// /userinfo should succeed.
	assertUserInfoStatus(t, env, accessTok, http.StatusOK)

	// /token refresh should succeed.
	params := url.Values{}
	params.Set("grant_type", "refresh_token")
	params.Set("client_id", clientID)
	params.Set("client_secret", "s")
	params.Set("refresh_token", refreshTok)
	rec := doTokenRequest(t, env, params)
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh with no revoke_before: want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
}
