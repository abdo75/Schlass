//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/abdo75/Schlass/internal/oidc"
	"github.com/abdo75/Schlass/internal/server"
	"github.com/abdo75/Schlass/internal/store"
)

// ---- helpers local to refresh tests ----

// doRefreshRequest fires POST /token with grant_type=refresh_token.
func doRefreshRequest(t *testing.T, env *TestEnv, clientID, clientSecret, refreshToken string) *httptest.ResponseRecorder {
	t.Helper()
	params := url.Values{}
	params.Set("grant_type", "refresh_token")
	params.Set("client_id", clientID)
	params.Set("client_secret", clientSecret)
	params.Set("refresh_token", refreshToken)
	return doTokenRequest(t, env, params)
}

// getInitialRefresh completes a full auth_code flow with offline_access and
// returns (clientID, rawRefreshToken). Uses the "s" client secret.
func getInitialRefresh(t *testing.T, env *TestEnv) (clientID, refreshTok string) {
	t.Helper()
	bootstrapKey(t, env)
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")
	cookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse42!")

	const redirect = "https://rp.example.com/cb"
	clientID = seedTokenClient(t, env, redirect, []string{"openid", "profile", "offline_access"})
	verifier, challenge := pkceParams()
	code := runAuthorizeAndGetCode(t, env, cookie, clientID, redirect, "openid profile offline_access", verifier, challenge)

	params := buildTokenParams(clientID, code, redirect, verifier)
	rec := doTokenRequest(t, env, params)
	if rec.Code != http.StatusOK {
		t.Fatalf("initial token exchange: got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	tok, _ := resp["refresh_token"].(string)
	if tok == "" {
		t.Fatal("no refresh_token in initial code exchange response")
	}
	return clientID, tok
}

// peekRefreshPayload reads the refresh token payload directly from Valkey
// without consuming it (uses the store's Get method).
func peekRefreshPayload(t *testing.T, env *TestEnv, rawToken string) *oidc.RefreshPayload {
	t.Helper()
	rs := oidc.NewRefreshStore(env.ValkeyClient)
	payload, err := rs.Get(context.Background(), rawToken)
	if err != nil {
		t.Fatalf("peekRefreshPayload: %v", err)
	}
	return payload
}

// assertAuditRowWithMetadata returns the metadata JSON for the first matching
// audit row with the given event_type and outcome.
func assertAuditRowWithMetadata(t *testing.T, env *TestEnv, eventType, outcome string) map[string]any {
	t.Helper()
	var raw []byte
	err := env.Pool.QueryRow(context.Background(),
		`SELECT metadata FROM audit_logs WHERE event_type=$1 AND outcome=$2 ORDER BY created_at DESC LIMIT 1`,
		eventType, outcome,
	).Scan(&raw)
	if err != nil {
		t.Fatalf("assertAuditRowWithMetadata(%q,%q): %v", eventType, outcome, err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	return m
}

// ---- Tests ----

func TestTokenRefresh_HappyPath_IssuesNewAccessAndRotatesRefresh(t *testing.T) {
	env := NewTestEnv(t)
	clientID, refreshTok := getInitialRefresh(t, env)

	// Verify refresh exists in Valkey before rotating.
	rs := oidc.NewRefreshStore(env.ValkeyClient)
	origPayload, err := rs.Get(context.Background(), refreshTok)
	if err != nil {
		t.Fatalf("initial refresh not in Valkey: %v", err)
	}
	origFamilyID := origPayload.FamilyID

	// Rotate.
	rec := doRefreshRequest(t, env, clientID, "s", refreshTok)
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh: expected 200 got %d body=%s", rec.Code, rec.Body.String())
	}
	assertCacheControlNoStore(t, rec)

	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	accessTok, _ := resp["access_token"].(string)
	idTok, _ := resp["id_token"].(string)
	newRefresh, _ := resp["refresh_token"].(string)
	tokenType, _ := resp["token_type"].(string)
	expiresIn, _ := resp["expires_in"].(float64)

	if accessTok == "" {
		t.Fatal("access_token missing in refresh response")
	}
	if idTok == "" {
		t.Fatal("id_token missing in refresh response")
	}
	if newRefresh == "" {
		t.Fatal("refresh_token missing in refresh response")
	}
	if tokenType != "Bearer" {
		t.Fatalf("token_type=%q want Bearer", tokenType)
	}
	if expiresIn != 900 {
		t.Fatalf("expires_in=%.0f want 900", expiresIn)
	}

	// New refresh must have the same family_id.
	newPayload := peekRefreshPayload(t, env, newRefresh)
	if newPayload.FamilyID != origFamilyID {
		t.Fatalf("new refresh family_id=%q want %q", newPayload.FamilyID, origFamilyID)
	}

	// Verify new access token parses correctly with a fresh jti.
	keyStore := store.NewSigningKeyStore()
	keys, err := keyStore.ListPublishable(context.Background(), env.Pool)
	if err != nil || len(keys) == 0 {
		t.Fatalf("list publishable keys: %v", err)
	}
	lookup := func(kid string) ([]byte, error) {
		for _, k := range keys {
			if k.ID.String() == kid {
				return k.PublicKeyPEM, nil
			}
		}
		return nil, fmt.Errorf("kid not found: %s", kid)
	}
	claims, err := oidc.ParseAndVerifyAccessToken(accessTok, lookup)
	if err != nil {
		t.Fatalf("verify rotated access token: %v", err)
	}
	if claims.JTI == "" {
		t.Fatal("new access token jti is empty")
	}

	// Audit row for refresh.
	if n := countAuditRows(t, env, "oidc.token.refreshed", "success"); n != 1 {
		t.Fatalf("expected 1 oidc.token.refreshed audit row, got %d", n)
	}

	// Old refresh must now trigger reuse detection.
	rec2 := doRefreshRequest(t, env, clientID, "s", refreshTok)
	assertTokenError(t, rec2, http.StatusBadRequest, "invalid_grant")
}

func TestTokenRefresh_ReusedRefresh_RevokesFamilyAndAuditsReuseDetected(t *testing.T) {
	env := NewTestEnv(t)
	clientID, refreshA := getInitialRefresh(t, env)

	// First rotation: A → B (happy path).
	rec1 := doRefreshRequest(t, env, clientID, "s", refreshA)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first rotation: %d %s", rec1.Code, rec1.Body.String())
	}
	var resp1 map[string]any
	_ = json.NewDecoder(rec1.Body).Decode(&resp1)
	refreshB, _ := resp1["refresh_token"].(string)
	if refreshB == "" {
		t.Fatal("no refresh_token after first rotation")
	}

	// Re-present refresh_A → reuse detected, family revoked.
	rec2 := doRefreshRequest(t, env, clientID, "s", refreshA)
	assertTokenError(t, rec2, http.StatusBadRequest, "invalid_grant")

	// refresh_B must also be dead (family revoked).
	rs := oidc.NewRefreshStore(env.ValkeyClient)
	if _, err := rs.Get(context.Background(), refreshB); err == nil {
		t.Fatal("refresh_B should be revoked after reuse of refresh_A (family revoke)")
	}

	// Audit row for reuse.
	if n := countAuditRows(t, env, "oidc.refresh.reuse_detected", "failure"); n != 1 {
		t.Fatalf("expected 1 oidc.refresh.reuse_detected audit row, got %d", n)
	}
	meta := assertAuditRowWithMetadata(t, env, "oidc.refresh.reuse_detected", "failure")
	if meta["family_id"] == "" || meta["family_id"] == nil {
		t.Fatalf("oidc.refresh.reuse_detected metadata missing family_id, got %v", meta)
	}

	// Presenting refresh_B (dead) now returns unknown/expired, not another reuse event.
	rec3 := doRefreshRequest(t, env, clientID, "s", refreshB)
	assertTokenError(t, rec3, http.StatusBadRequest, "invalid_grant")
}

func TestTokenRefresh_UnknownToken_400InvalidGrant(t *testing.T) {
	env := NewTestEnv(t)
	bootstrapKey(t, env)
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")

	const redirect = "https://rp.example.com/cb"
	clientID := seedTokenClient(t, env, redirect, []string{"openid", "offline_access"})

	rec := doRefreshRequest(t, env, clientID, "s", "totally-unknown-token-value")
	assertTokenError(t, rec, http.StatusBadRequest, "invalid_grant")
}

func TestTokenRefresh_ClientMismatch_400InvalidGrant(t *testing.T) {
	env := NewTestEnv(t)
	clientA, refreshTok := getInitialRefresh(t, env)

	// Seed a second client with the same secret.
	const redirect = "https://rp.example.com/cb"
	clientB := seedTokenClient(t, env, redirect, []string{"openid", "offline_access"})
	_ = clientA

	// Present refresh issued for client A using client B credentials.
	rec := doRefreshRequest(t, env, clientB, "s", refreshTok)
	assertTokenError(t, rec, http.StatusBadRequest, "invalid_grant")
}

func TestTokenRefresh_WrongClientSecret_401InvalidClient(t *testing.T) {
	env := NewTestEnv(t)
	clientID, refreshTok := getInitialRefresh(t, env)

	// Wrong secret.
	rec := doRefreshRequest(t, env, clientID, "wrong-secret", refreshTok)
	assertTokenError(t, rec, http.StatusUnauthorized, "invalid_client")

	if n := countAuditRows(t, env, "oidc.client.auth_failed", "failure"); n < 1 {
		t.Fatalf("expected at least 1 oidc.client.auth_failed audit row, got %d", n)
	}
}

func TestTokenRefresh_DisabledUser_RevokesFamily(t *testing.T) {
	env := NewTestEnv(t)
	clientID, refreshTok := getInitialRefresh(t, env)

	// Capture family_id before disabling.
	origPayload := peekRefreshPayload(t, env, refreshTok)

	// Disable the user between refresh issuance and rotation attempt.
	userID := env.GetUserIDByEmail(t, "admin@example.com")
	if _, err := env.Pool.Exec(context.Background(),
		`UPDATE users SET status='disabled' WHERE id=$1`, userID,
	); err != nil {
		t.Fatalf("disable user: %v", err)
	}

	rec := doRefreshRequest(t, env, clientID, "s", refreshTok)
	assertTokenError(t, rec, http.StatusBadRequest, "invalid_grant")

	// Family must be revoked.
	rs := oidc.NewRefreshStore(env.ValkeyClient)
	if _, err := rs.Get(context.Background(), refreshTok); err == nil {
		t.Fatal("refresh token should be revoked after user disabled")
	}

	// Audit row.
	if n := countAuditRows(t, env, "oidc.refresh.user_disabled", "failure"); n != 1 {
		t.Fatalf("expected 1 oidc.refresh.user_disabled audit row, got %d", n)
	}
	meta := assertAuditRowWithMetadata(t, env, "oidc.refresh.user_disabled", "failure")
	if meta["family_id"] != origPayload.FamilyID {
		t.Fatalf("user_disabled audit family_id=%v want %q", meta["family_id"], origPayload.FamilyID)
	}
}

func TestTokenRefresh_ExpiredRefresh_400InvalidGrant(t *testing.T) {
	env := NewTestEnv(t)
	clientID, refreshTok := getInitialRefresh(t, env)

	// Overwrite the Valkey payload with an exp in the past by creating a new
	// entry under the same hash — simplest approach is to use the store's
	// MarkUsed to make it look consumed (expired), then delete it directly.
	// Instead: delete the key directly so Consume returns ErrRefreshUnknownOrExpired.
	hashKey := "oidc:refresh:" + sha256hex(refreshTok)
	if err := env.ValkeyClient.Del(context.Background(), hashKey).Err(); err != nil {
		t.Fatalf("delete refresh from Valkey: %v", err)
	}

	rec := doRefreshRequest(t, env, clientID, "s", refreshTok)
	assertTokenError(t, rec, http.StatusBadRequest, "invalid_grant")
}

func TestTokenRefresh_MultipleRotations_PreserveAbsoluteExp(t *testing.T) {
	env := NewTestEnv(t)
	clientID, refresh0 := getInitialRefresh(t, env)

	// Record the original exp from the first refresh token.
	origPayload := peekRefreshPayload(t, env, refresh0)
	origExp := origPayload.Expires

	// Rotate 3 times.
	current := refresh0
	for i := 0; i < 3; i++ {
		rec := doRefreshRequest(t, env, clientID, "s", current)
		if rec.Code != http.StatusOK {
			t.Fatalf("rotation %d: got %d body=%s", i+1, rec.Code, rec.Body.String())
		}
		var resp map[string]any
		_ = json.NewDecoder(rec.Body).Decode(&resp)
		next, _ := resp["refresh_token"].(string)
		if next == "" {
			t.Fatalf("rotation %d: no refresh_token in response", i+1)
		}
		current = next
	}

	// The final refresh must carry the same absolute exp as the original.
	finalPayload := peekRefreshPayload(t, env, current)
	if finalPayload.Expires != origExp {
		t.Fatalf("after 3 rotations: exp=%d want original %d (absolute exp must not reset)",
			finalPayload.Expires, origExp)
	}
}

func TestTokenRefresh_MissingRefreshToken_400InvalidRequest(t *testing.T) {
	env := NewTestEnv(t)
	bootstrapKey(t, env)
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")

	const redirect = "https://rp.example.com/cb"
	clientID := seedTokenClient(t, env, redirect, []string{"openid"})

	params := url.Values{}
	params.Set("grant_type", "refresh_token")
	params.Set("client_id", clientID)
	params.Set("client_secret", "s")
	// Deliberately omit refresh_token.

	rec := doTokenRequest(t, env, params)
	assertTokenError(t, rec, http.StatusBadRequest, "invalid_request")
}

func TestTokenRefresh_RateLimitEnforced_429(t *testing.T) {
	const lowLimit = int64(3)
	const redirect = "https://rp.example.com/cb"

	env := NewTestEnv(t)
	bootstrapKey(t, env)
	deps := env.BuildDeps()
	deps.TokenRateLimit = lowLimit
	router, err := server.BuildRouter(deps)
	if err != nil {
		t.Fatalf("build router with low token rate limit: %v", err)
	}
	env.Router = router

	clientID := seedTokenClient(t, env, redirect, []string{"openid", "offline_access"})

	// Fire lowLimit+1 refresh requests. The token doesn't need to be valid —
	// rate limiting fires before Valkey lookup, so any value triggers the counter.
	var last *httptest.ResponseRecorder
	for i := 0; i <= int(lowLimit); i++ {
		params := url.Values{}
		params.Set("grant_type", "refresh_token")
		params.Set("client_id", clientID)
		params.Set("client_secret", "s")
		params.Set("refresh_token", fmt.Sprintf("bad-refresh-%d", i))

		req := httptest.NewRequestWithContext(
			t.Context(), "POST", "/token",
			strings.NewReader(params.Encode()),
		)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		env.Router.ServeHTTP(rec, req)
		last = rec
	}

	if last.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on request %d, got %d body=%s", lowLimit+1, last.Code, last.Body.String())
	}
	assertTokenError(t, last, http.StatusTooManyRequests, "invalid_request")
}
