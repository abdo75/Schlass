//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// doUserInfoRequest fires GET /userinfo with the given Bearer token.
func doUserInfoRequest(t *testing.T, env *TestEnv, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), "GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	return rec
}

func TestUserInfo_AllScopes_EmitsFullClaimSet(t *testing.T) {
	env := NewTestEnv(t)
	bootstrapKey(t, env)

	userID := env.SeedAdmin(t, "alice@example.com", "CorrectHorse1Battery")
	cookie := env.LoginAsAdmin(t, "alice@example.com", "CorrectHorse1Battery")

	const redirect = "https://rp.example.com/cb"
	clientID := seedTokenClient(t, env, redirect, []string{"openid", "profile", "email"})
	verifier, challenge := pkceParams()
	code := runAuthorizeAndGetCode(t, env, cookie, clientID, redirect, "openid profile email", verifier, challenge)

	params := buildTokenParams(clientID, code, redirect, verifier)
	rec := doTokenRequest(t, env, params)
	if rec.Code != http.StatusOK {
		t.Fatalf("token: status=%d body=%s", rec.Code, rec.Body.String())
	}
	var tokenResp map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&tokenResp)
	accessTok, _ := tokenResp["access_token"].(string)
	if accessTok == "" {
		t.Fatal("access_token missing from token response")
	}

	uiRec := doUserInfoRequest(t, env, accessTok)
	if uiRec.Code != http.StatusOK {
		t.Fatalf("userinfo: status=%d body=%s", uiRec.Code, uiRec.Body.String())
	}

	var body map[string]any
	if err := json.NewDecoder(uiRec.Body).Decode(&body); err != nil {
		t.Fatalf("decode userinfo: %v", err)
	}
	if body["sub"] != userID.String() {
		t.Fatalf("sub=%v want=%s", body["sub"], userID)
	}
	if body["preferred_username"] != "alice@example.com" {
		t.Fatalf("preferred_username=%v", body["preferred_username"])
	}
	if body["email"] != "alice@example.com" {
		t.Fatalf("email=%v", body["email"])
	}
	if body["email_verified"] != true {
		t.Fatalf("email_verified=%v", body["email_verified"])
	}
	// /userinfo must not include iss or aud — it's a plain JSON doc, not a JWT.
	if body["iss"] != nil || body["aud"] != nil {
		t.Fatalf("userinfo must not include iss/aud: %+v", body)
	}
}

func TestUserInfo_OpenIDOnly_OmitsProfileAndEmail(t *testing.T) {
	env := NewTestEnv(t)
	bootstrapKey(t, env)

	userID := env.SeedAdmin(t, "b@example.com", "CorrectHorse1Battery")
	cookie := env.LoginAsAdmin(t, "b@example.com", "CorrectHorse1Battery")

	const redirect = "https://rp.example.com/cb"
	clientID := seedTokenClient(t, env, redirect, []string{"openid", "profile", "email"})
	verifier, challenge := pkceParams()
	code := runAuthorizeAndGetCode(t, env, cookie, clientID, redirect, "openid", verifier, challenge)

	params := buildTokenParams(clientID, code, redirect, verifier)
	rec := doTokenRequest(t, env, params)
	if rec.Code != http.StatusOK {
		t.Fatalf("token: status=%d body=%s", rec.Code, rec.Body.String())
	}
	var tokenResp map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&tokenResp)
	accessTok, _ := tokenResp["access_token"].(string)

	uiRec := doUserInfoRequest(t, env, accessTok)
	if uiRec.Code != http.StatusOK {
		t.Fatalf("userinfo: status=%d", uiRec.Code)
	}
	var body map[string]any
	_ = json.NewDecoder(uiRec.Body).Decode(&body)

	if body["sub"] == nil {
		t.Fatal("sub must always be present")
	}
	if body["sub"] != userID.String() {
		t.Fatalf("sub=%v want=%s", body["sub"], userID)
	}
	if _, has := body["preferred_username"]; has {
		t.Fatal("preferred_username should be absent for openid-only scope")
	}
	if _, has := body["email"]; has {
		t.Fatal("email should be absent for openid-only scope")
	}
}

func TestUserInfo_ProfileOnly_OmitsEmail(t *testing.T) {
	env := NewTestEnv(t)
	bootstrapKey(t, env)

	env.SeedAdmin(t, "c@example.com", "CorrectHorse1Battery")
	cookie := env.LoginAsAdmin(t, "c@example.com", "CorrectHorse1Battery")

	const redirect = "https://rp.example.com/cb"
	clientID := seedTokenClient(t, env, redirect, []string{"openid", "profile", "email"})
	verifier, challenge := pkceParams()
	code := runAuthorizeAndGetCode(t, env, cookie, clientID, redirect, "openid profile", verifier, challenge)

	params := buildTokenParams(clientID, code, redirect, verifier)
	rec := doTokenRequest(t, env, params)
	if rec.Code != http.StatusOK {
		t.Fatalf("token: status=%d", rec.Code)
	}
	var tokenResp map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&tokenResp)
	accessTok, _ := tokenResp["access_token"].(string)

	uiRec := doUserInfoRequest(t, env, accessTok)
	if uiRec.Code != http.StatusOK {
		t.Fatalf("userinfo: status=%d", uiRec.Code)
	}
	var body map[string]any
	_ = json.NewDecoder(uiRec.Body).Decode(&body)

	if body["preferred_username"] != "c@example.com" {
		t.Fatal("preferred_username missing for profile scope")
	}
	if _, has := body["email"]; has {
		t.Fatal("email should be absent for profile-only scope")
	}
}

func TestUserInfo_MissingBearerToken_401(t *testing.T) {
	env := NewTestEnv(t)
	bootstrapKey(t, env)

	req := httptest.NewRequestWithContext(t.Context(), "GET", "/userinfo", nil)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 got %d", rec.Code)
	}
}

func TestUserInfo_TamperedToken_401(t *testing.T) {
	env := NewTestEnv(t)
	bootstrapKey(t, env)

	env.SeedAdmin(t, "d@example.com", "CorrectHorse1Battery")
	cookie := env.LoginAsAdmin(t, "d@example.com", "CorrectHorse1Battery")

	const redirect = "https://rp.example.com/cb"
	clientID := seedTokenClient(t, env, redirect, []string{"openid", "profile"})
	verifier, challenge := pkceParams()
	code := runAuthorizeAndGetCode(t, env, cookie, clientID, redirect, "openid profile", verifier, challenge)

	params := buildTokenParams(clientID, code, redirect, verifier)
	rec := doTokenRequest(t, env, params)
	if rec.Code != http.StatusOK {
		t.Fatalf("token: status=%d", rec.Code)
	}
	var tokenResp map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&tokenResp)
	accessTok, _ := tokenResp["access_token"].(string)

	// Corrupt the signature by replacing the last 8 characters.
	// This is more robust than flipping one character (which may still produce
	// a valid base64url segment in degenerate cases).
	tampered := accessTok[:len(accessTok)-8] + "XXXXXXXX"
	uiRec := doUserInfoRequest(t, env, tampered)
	if uiRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 got %d", uiRec.Code)
	}
}

// TestUserInfo_NoAuditRowOnSuccessfulRead asserts that successful userinfo
// reads are intentionally NOT audited (see userinfo.go: routine self-reads
// are not security-relevant per ISO 27001 / NIST 800-53). This guards the
// trim from regression — a future change that re-introduces the emission
// would be flagged here.
func TestUserInfo_NoAuditRowOnSuccessfulRead(t *testing.T) {
	env := NewTestEnv(t)
	bootstrapKey(t, env)

	env.SeedAdmin(t, "e@example.com", "CorrectHorse1Battery")
	cookie := env.LoginAsAdmin(t, "e@example.com", "CorrectHorse1Battery")

	const redirect = "https://rp.example.com/cb"
	clientID := seedTokenClient(t, env, redirect, []string{"openid", "profile"})
	verifier, challenge := pkceParams()
	code := runAuthorizeAndGetCode(t, env, cookie, clientID, redirect, "openid profile", verifier, challenge)

	params := buildTokenParams(clientID, code, redirect, verifier)
	rec := doTokenRequest(t, env, params)
	if rec.Code != http.StatusOK {
		t.Fatalf("token: status=%d", rec.Code)
	}
	var tokenResp map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&tokenResp)
	accessTok, _ := tokenResp["access_token"].(string)

	uiRec := doUserInfoRequest(t, env, accessTok)
	if uiRec.Code != http.StatusOK {
		t.Fatalf("userinfo: status=%d body=%s", uiRec.Code, uiRec.Body.String())
	}

	var count int
	_ = env.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_logs WHERE event_type='oidc.userinfo.accessed'`,
	).Scan(&count)
	if count != 0 {
		t.Fatalf("expected 0 oidc.userinfo.accessed rows after trim, got %d", count)
	}
}

func TestUserInfo_EndToEnd_AuthorizeThroughTokenThroughUserInfo(t *testing.T) {
	env := NewTestEnv(t)
	bootstrapKey(t, env)

	// Seed user + client.
	userID := env.SeedAdmin(t, "oidc-e2e@example.com", "CorrectHorse1Battery")
	cookie := env.LoginAsAdmin(t, "oidc-e2e@example.com", "CorrectHorse1Battery")

	const redirect = "https://rp.example.com/callback"
	clientID := seedTokenClient(t, env, redirect, []string{"openid", "profile", "email"})

	// /authorize → code.
	verifier, challenge := pkceParams()
	code := runAuthorizeAndGetCode(t, env, cookie, clientID, redirect, "openid profile email", verifier, challenge)

	// POST /token → access_token.
	params := buildTokenParams(clientID, code, redirect, verifier)
	tokenRec := doTokenRequest(t, env, params)
	if tokenRec.Code != http.StatusOK {
		t.Fatalf("token: status=%d body=%s", tokenRec.Code, tokenRec.Body.String())
	}
	var tokenResp map[string]any
	if err := json.NewDecoder(tokenRec.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	accessTok, _ := tokenResp["access_token"].(string)
	if accessTok == "" {
		t.Fatal("access_token missing")
	}

	// GET /userinfo → claim set.
	uiRec := doUserInfoRequest(t, env, accessTok)
	if uiRec.Code != http.StatusOK {
		t.Fatalf("userinfo: status=%d body=%s", uiRec.Code, uiRec.Body.String())
	}
	var claims map[string]any
	if err := json.NewDecoder(uiRec.Body).Decode(&claims); err != nil {
		t.Fatalf("decode userinfo: %v", err)
	}

	// Assert the full claim set matches the seeded user.
	if claims["sub"] != userID.String() {
		t.Fatalf("sub=%v want=%s", claims["sub"], userID)
	}
	if claims["preferred_username"] != "oidc-e2e@example.com" {
		t.Fatalf("preferred_username=%v", claims["preferred_username"])
	}
	if claims["email"] != "oidc-e2e@example.com" {
		t.Fatalf("email=%v", claims["email"])
	}
	if claims["email_verified"] != true {
		t.Fatalf("email_verified=%v", claims["email_verified"])
	}
	// Plain JSON — no JWT wrapper fields.
	if claims["iss"] != nil || claims["aud"] != nil {
		t.Fatalf("iss/aud must be absent from userinfo: %+v", claims)
	}
}
