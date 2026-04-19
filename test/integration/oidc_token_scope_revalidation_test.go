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
