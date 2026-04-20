//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// TestPasswordResetConfirm_RevokesOutstandingOIDCTokens proves the full
// revocation chain end-to-end:
//  1. Victim logs in + mints an OIDC access token via the standard
//     auth_code + PKCE flow (same idiom as sessions_terminate_test.go).
//  2. /userinfo with the AT returns 200 (sanity — pre-reset).
//  3. A valid reset token is created for the victim.
//  4. POST /api/password-reset/confirm with a policy-compliant new
//     password commits, bumps user:revoke_before, wipes sessions.
//  5. /userinfo with the pre-existing AT is now rejected with 401 —
//     bearer_auth middleware reads the fresh revoke_before cutoff and
//     the AT's iat is strictly less than cutoff.
//
// Companion to TestTerminateAllSessions_BumpsRevokeBefore (M1) — same
// shape, different bump trigger. Closes the "outstanding OIDC tokens
// before reset now fail" claim in a reproducible CI-gated way, so the
// invariant can't regress silently.
func TestPasswordResetConfirm_RevokesOutstandingOIDCTokens(t *testing.T) {
	env := NewTestEnv(t)
	bootstrapKey(t, env)

	victimID := env.SeedAdmin(t, "reset-victim@example.com", "CorrectHorse1Battery")
	victimCookie := env.LoginAsAdmin(t, "reset-victim@example.com", "CorrectHorse1Battery")

	// Mint AT via auth_code + PKCE (copy of the M1 sessions_terminate
	// idiom — see sessions_terminate_test.go for the helper chain).
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

	// Sanity: pre-reset /userinfo accepts the AT.
	preRec := doUserInfoRequest(t, env, accessToken)
	if preRec.Code != http.StatusOK {
		t.Fatalf("pre-reset /userinfo: want 200, got %d body=%s", preRec.Code, preRec.Body.String())
	}

	// Mint a live reset token for the victim + confirm it with a
	// policy-compliant new password. Goes through the real handler chain
	// (SELECT FOR UPDATE, password policy check, password hash, mark used,
	// audit in-tx, commit, post-commit revoke_before + session wipe).
	token := env.InsertResetToken(t, victimID, 30*time.Minute)
	body, _ := json.Marshal(map[string]any{
		"token":    token,
		"password": "BrandNewCorrectHorse1!",
	})
	confirmRec := publicPost(t, env, "/api/password-reset/confirm", body)
	if confirmRec.Code != http.StatusOK {
		t.Fatalf("confirm: want 200, got %d body=%s", confirmRec.Code, confirmRec.Body.String())
	}

	// Post-reset: /userinfo with the SAME AT must now fail with 401.
	// bearer_auth reads user:revoke_before from Valkey, compares against
	// the AT's iat claim, and writes WWW-Authenticate: Bearer invalid_token.
	postRec := doUserInfoRequest(t, env, accessToken)
	if postRec.Code != http.StatusUnauthorized {
		t.Fatalf("post-reset /userinfo: want 401, got %d body=%s", postRec.Code, postRec.Body.String())
	}
}
