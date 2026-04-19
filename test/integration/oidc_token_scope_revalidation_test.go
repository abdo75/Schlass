//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---- shared helpers for scope-revalidation tests ----

// decodeRefreshToken extracts the refresh_token from a successful /token response.
func decodeRefreshToken(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	tok, _ := resp["refresh_token"].(string)
	if tok == "" {
		t.Fatal("no refresh_token in response")
	}
	return tok
}

// decodeScope extracts the scope string from a /token response body.
func decodeScope(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	scope, _ := resp["scope"].(string)
	return scope
}

// containsScope reports whether scope (space-separated) contains the given word.
func containsScope(scope, word string) bool {
	for _, s := range strings.Split(scope, " ") {
		if s == word {
			return true
		}
	}
	return false
}

// ---- Refresh grant scope + grant re-validation (T4.2) ----

// TestRefreshGrant_ScopeNarrowed confirms that narrowing allowed_scopes on a
// client causes the next refresh grant to emit a narrower AT (intersection),
// not the original full set.
func TestRefreshGrant_ScopeNarrowed(t *testing.T) {
	env := NewTestEnv(t)
	bootstrapKey(t, env)
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")
	cookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse42!")

	const redirect = "https://rp.example.com/cb"
	clientID := seedTokenClient(t, env, redirect, []string{"openid", "profile", "email", "offline_access"})
	verifier, challenge := pkceParams()
	code := runAuthorizeAndGetCode(t, env, cookie, clientID, redirect, "openid profile offline_access", verifier, challenge)

	params := buildTokenParams(clientID, code, redirect, verifier)
	rec := doTokenRequest(t, env, params)
	if rec.Code != http.StatusOK {
		t.Fatalf("initial token exchange: got %d body=%s", rec.Code, rec.Body.String())
	}

	refreshTok := decodeRefreshToken(t, rec)

	// Admin narrows allowed_scopes — remove profile from what the client allows.
	if _, err := env.Pool.Exec(context.Background(),
		`UPDATE clients SET allowed_scopes = ARRAY['openid','email','offline_access'] WHERE id = $1`, clientID,
	); err != nil {
		t.Fatalf("narrow allowed_scopes: %v", err)
	}

	// Refresh grant should succeed — openid + offline_access remain in the intersection.
	rec2 := doRefreshRequest(t, env, clientID, "s", refreshTok)
	if rec2.Code != http.StatusOK {
		t.Fatalf("refresh after scope narrow: got %d body=%s", rec2.Code, rec2.Body.String())
	}
	// Scope field in response should not contain profile.
	scope := decodeScope(t, rec2)
	if containsScope(scope, "profile") {
		t.Fatalf("expected profile removed from narrowed refresh response, got scope=%q", scope)
	}
	if !containsScope(scope, "openid") {
		t.Fatalf("expected openid in narrowed refresh response, got scope=%q", scope)
	}
}

// TestRefreshGrant_OfflineAccessRemovedRejectsScope confirms that removing all
// overlapping scopes causes the refresh grant to return invalid_scope.
func TestRefreshGrant_OfflineAccessRemovedRejectsScope(t *testing.T) {
	env := NewTestEnv(t)
	clientID, refreshTok := getInitialRefresh(t, env)

	// Narrow allowed_scopes to only 'email' — none of the granted scopes
	// (openid, profile, offline_access) remain allowed.
	if _, err := env.Pool.Exec(context.Background(),
		`UPDATE clients SET allowed_scopes = ARRAY['email'] WHERE id = $1`, clientID,
	); err != nil {
		t.Fatalf("narrow allowed_scopes: %v", err)
	}

	rec := doRefreshRequest(t, env, clientID, "s", refreshTok)
	assertTokenError(t, rec, http.StatusBadRequest, "invalid_scope")
}

// TestRefreshGrant_RefreshTokenGrantRemovedRejectsUnauthorizedClient confirms
// that removing refresh_token from allowed_grant_types causes the refresh
// grant to reject with unauthorized_client.
func TestRefreshGrant_RefreshTokenGrantRemovedRejectsUnauthorizedClient(t *testing.T) {
	env := NewTestEnv(t)
	clientID, refreshTok := getInitialRefresh(t, env)

	// Remove refresh_token from the client's allowed grant types.
	if _, err := env.Pool.Exec(context.Background(),
		`UPDATE clients SET allowed_grant_types = ARRAY['authorization_code'] WHERE id = $1`, clientID,
	); err != nil {
		t.Fatalf("remove refresh_token grant: %v", err)
	}

	rec := doRefreshRequest(t, env, clientID, "s", refreshTok)
	assertTokenError(t, rec, http.StatusBadRequest, "unauthorized_client")
}

// ---- Auth_code grant scope + grant re-validation (T4.3) ----

// TestAuthCodeGrant_ScopeNarrowedBetweenAuthorizeAndTokenExchange confirms that
// if allowed_scopes is narrowed between /authorize (code issuance) and /token
// (code exchange), the AT is issued with the narrowed scope.
func TestAuthCodeGrant_ScopeNarrowedBetweenAuthorizeAndTokenExchange(t *testing.T) {
	env := NewTestEnv(t)
	bootstrapKey(t, env)
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")
	cookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse42!")

	const redirect = "https://rp.example.com/cb"
	clientID := seedTokenClient(t, env, redirect, []string{"openid", "profile", "email"})
	verifier, challenge := pkceParams()
	code := runAuthorizeAndGetCode(t, env, cookie, clientID, redirect, "openid profile", verifier, challenge)

	// Admin narrows allowed_scopes between /authorize and /token — remove profile.
	if _, err := env.Pool.Exec(context.Background(),
		`UPDATE clients SET allowed_scopes = ARRAY['openid','email'] WHERE id = $1`, clientID,
	); err != nil {
		t.Fatalf("narrow allowed_scopes: %v", err)
	}

	params := buildTokenParams(clientID, code, redirect, verifier)
	rec := doTokenRequest(t, env, params)
	if rec.Code != http.StatusOK {
		t.Fatalf("token exchange after scope narrow: got %d body=%s", rec.Code, rec.Body.String())
	}
	// profile should be removed from the response scope.
	scope := decodeScope(t, rec)
	if containsScope(scope, "profile") {
		t.Fatalf("expected profile removed from narrowed auth_code response, got scope=%q", scope)
	}
	if !containsScope(scope, "openid") {
		t.Fatalf("expected openid in narrowed auth_code response, got scope=%q", scope)
	}
}

// TestAuthCodeGrant_AllScopesRemovedRejectsInvalidScope confirms that if all
// granted scopes are removed from allowed_scopes, the auth_code exchange returns
// invalid_scope.
func TestAuthCodeGrant_AllScopesRemovedRejectsInvalidScope(t *testing.T) {
	env := NewTestEnv(t)
	bootstrapKey(t, env)
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")
	cookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse42!")

	const redirect = "https://rp.example.com/cb"
	clientID := seedTokenClient(t, env, redirect, []string{"openid", "profile"})
	verifier, challenge := pkceParams()
	code := runAuthorizeAndGetCode(t, env, cookie, clientID, redirect, "openid profile", verifier, challenge)

	// Admin removes all relevant scopes.
	if _, err := env.Pool.Exec(context.Background(),
		`UPDATE clients SET allowed_scopes = ARRAY['email'] WHERE id = $1`, clientID,
	); err != nil {
		t.Fatalf("remove allowed_scopes: %v", err)
	}

	params := buildTokenParams(clientID, code, redirect, verifier)
	rec := doTokenRequest(t, env, params)
	assertTokenError(t, rec, http.StatusBadRequest, "invalid_scope")
}

// TestAuthCodeGrant_AuthCodeGrantRemovedRejectsUnauthorizedClient confirms that
// removing authorization_code from allowed_grant_types causes /token to reject
// with unauthorized_client.
func TestAuthCodeGrant_AuthCodeGrantRemovedRejectsUnauthorizedClient(t *testing.T) {
	env := NewTestEnv(t)
	bootstrapKey(t, env)
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")
	cookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse42!")

	const redirect = "https://rp.example.com/cb"
	clientID := seedTokenClient(t, env, redirect, []string{"openid", "profile"})
	verifier, challenge := pkceParams()
	code := runAuthorizeAndGetCode(t, env, cookie, clientID, redirect, "openid profile", verifier, challenge)

	// Remove authorization_code from allowed grant types.
	if _, err := env.Pool.Exec(context.Background(),
		`UPDATE clients SET allowed_grant_types = ARRAY['refresh_token'] WHERE id = $1`, clientID,
	); err != nil {
		t.Fatalf("remove authorization_code grant: %v", err)
	}

	params := buildTokenParams(clientID, code, redirect, verifier)
	rec := doTokenRequest(t, env, params)
	assertTokenError(t, rec, http.StatusBadRequest, "unauthorized_client")
}
