//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestTerminateAllSessions_BumpsRevokeBefore asserts that
// DELETE /api/users/:id/sessions not only deletes the Valkey admin-web
// sessions but ALSO bumps user:revoke_before so outstanding OIDC access +
// refresh tokens for the target user fail on next use. Closes the Sprint 3
// "force-terminate kills all tokens" claim gap (Sprint 6a T1 / M1).
func TestTerminateAllSessions_BumpsRevokeBefore(t *testing.T) {
	env := NewTestEnv(t)
	bootstrapKey(t, env)

	// Two admins: the terminator ("admin") and the victim ("victim"). Both
	// are super_admin because SeedAdmin hardcodes that role; the terminate
	// handler only cares that the actor has users.terminate_sessions
	// permission (super_admin has it), and the victim's role is irrelevant
	// to the revoke_before cutoff semantics under test.
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")
	victimID := env.SeedAdmin(t, "victim@example.com", "CorrectHorse1Battery")

	adminCookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse42!")
	victimCookie := env.LoginAsAdmin(t, "victim@example.com", "CorrectHorse1Battery")

	// Mint a bearer AT for the victim via the standard auth_code + PKCE flow.
	// The /authorize call uses the victim's session cookie (resource owner).
	const redirect = "https://rp.example.com/cb"
	clientID := seedTokenClient(t, env, redirect, []string{"openid", "profile", "email", "offline_access"})
	verifier, challenge := pkceParams()
	code := runAuthorizeAndGetCode(t, env, victimCookie, clientID, redirect,
		"openid profile email offline_access", verifier, challenge)
	tokRec := doTokenRequest(t, env, buildTokenParams(clientID, code, redirect, verifier))
	if tokRec.Code != http.StatusOK {
		t.Fatalf("token exchange: status=%d body=%s", tokRec.Code, tokRec.Body.String())
	}
	var tokResp map[string]any
	if err := json.NewDecoder(tokRec.Body).Decode(&tokResp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	accessToken, _ := tokResp["access_token"].(string)
	if accessToken == "" {
		t.Fatal("access_token missing from token response")
	}

	// Sanity: /userinfo accepts the AT before the terminate.
	preRec := doUserInfoRequest(t, env, accessToken)
	if preRec.Code != http.StatusOK {
		t.Fatalf("pre-terminate /userinfo: got %d body=%s", preRec.Code, preRec.Body.String())
	}

	// Admin terminates all sessions for the victim via the real admin API.
	delReq := httptest.NewRequestWithContext(t.Context(), "DELETE",
		"/api/users/"+victimID.String()+"/sessions", nil)
	delReq.AddCookie(adminCookie)
	delRec := httptest.NewRecorder()
	env.Router.ServeHTTP(delRec, delReq)
	if delRec.Code != http.StatusNoContent {
		t.Fatalf("terminate all sessions: want 204, got %d body=%s", delRec.Code, delRec.Body.String())
	}

	// Revoke-before must now exist in Valkey and be a fresh unix-seconds value.
	assertValkeyRevokeBefore(t, env, victimID.String())

	// Audit row with reason=sessions_terminated must exist.
	assertRevokeBeforeAuditRow(t, env, victimID.String(), "sessions_terminated")

	// /userinfo with the pre-existing AT must now be rejected with 401:
	// revoke_before cutoff is now strictly greater than the AT's iat, so
	// bearer_auth middleware writes WWW-Authenticate: Bearer invalid_token.
	postRec := doUserInfoRequest(t, env, accessToken)
	if postRec.Code != http.StatusUnauthorized {
		t.Fatalf("post-terminate /userinfo: want 401, got %d body=%s", postRec.Code, postRec.Body.String())
	}
}
