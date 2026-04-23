//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/abdo75/Schlass/internal/audit"
	signingkeys "github.com/abdo75/Schlass/internal/signingkeys"
	"github.com/abdo75/Schlass/internal/oidc"
	"github.com/abdo75/Schlass/internal/server"
)

// ---- helpers local to this file ----

// seedTokenClient inserts a confidential OIDC client that supports the given
// scopes (always appends offline_access to allowed_grant_types).
// Returns (clientID, rawSecret "s"). The secret hash is Argon2id("s").
func seedTokenClient(t *testing.T, env *TestEnv, redirectURI string, allowedScopes []string) string {
	t.Helper()
	// Re-use seedAuthorizeClient — it already hashes "s" and sets
	// allowed_grant_types = ['authorization_code','refresh_token'].
	return seedAuthorizeClient(t, env, redirectURI, allowedScopes)
}

// bootstrapKey ensures there is an active signing key in the test DB using the
// test environment's encryption key (32 zero bytes).
func bootstrapKey(t *testing.T, env *TestEnv) {
	t.Helper()
	if err := signingkeys.Bootstrap(
		context.Background(),
		env.Pool,
		audit.NewStore(),
		env.Cfg.EncryptionKey,
	); err != nil {
		t.Fatalf("bootstrapKey: %v", err)
	}
}

// pkceParams generates a deterministic PKCE verifier (32 bytes, base64url) and
// returns (verifier, challenge) where challenge = base64url(sha256(verifier)).
func pkceParams() (verifier, challenge string) {
	buf := make([]byte, 32)
	for i := range buf {
		buf[i] = byte(i + 1) // deterministic non-zero bytes
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf)
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return verifier, challenge
}

// runAuthorizeAndGetCode drives GET /authorize as an authenticated admin and
// returns the authorization code string. scopeParam is the space-joined scope
// list (e.g. "openid profile").
func runAuthorizeAndGetCode(
	t *testing.T,
	env *TestEnv,
	cookie *http.Cookie,
	clientID, redirectURI, scopeParam string,
	verifier, challenge string,
) string {
	t.Helper()
	v := url.Values{}
	v.Set("client_id", clientID)
	v.Set("redirect_uri", redirectURI)
	v.Set("response_type", "code")
	v.Set("state", "s")
	v.Set("scope", scopeParam)
	v.Set("code_challenge", challenge)
	v.Set("code_challenge_method", "S256")
	rawURL := "/authorize?" + v.Encode()

	req := httptest.NewRequestWithContext(t.Context(), "GET", rawURL, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize: expected 302 got %d body=%s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, redirectURI) {
		t.Fatalf("authorize: redirect not to RP, got %q", loc)
	}
	parsed, _ := url.Parse(loc)
	code := parsed.Query().Get("code")
	if code == "" {
		t.Fatalf("authorize: no code in redirect %q", loc)
	}
	return code
}

// doTokenRequest fires POST /token with form params and returns the recorder.
func doTokenRequest(t *testing.T, env *TestEnv, params url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(
		t.Context(), "POST", "/token",
		strings.NewReader(params.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	return rec
}

// assertTokenError decodes the response body and checks the error field.
func assertTokenError(t *testing.T, rec *httptest.ResponseRecorder, wantStatus int, wantErr string) {
	t.Helper()
	if rec.Code != wantStatus {
		t.Fatalf("expected status %d got %d body=%s", wantStatus, rec.Code, rec.Body.String())
	}
	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if got := body["error"]; got != wantErr {
		t.Fatalf("error=%q want %q", got, wantErr)
	}
}

// assertCacheControlNoStore confirms that the response includes Cache-Control: no-store.
func assertCacheControlNoStore(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if v := rec.Header().Get("Cache-Control"); v != "no-store" {
		t.Fatalf("Cache-Control=%q want no-store", v)
	}
}

// countAuditRows returns the number of audit_logs rows matching eventType and outcome.
func countAuditRows(t *testing.T, env *TestEnv, eventType, outcome string) int {
	t.Helper()
	var n int
	if err := env.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_logs WHERE event_type=$1 AND outcome=$2`,
		eventType, outcome,
	).Scan(&n); err != nil {
		t.Fatalf("countAuditRows(%q,%q): %v", eventType, outcome, err)
	}
	return n
}

// buildTokenParams constructs the standard authorization_code token params.
func buildTokenParams(clientID, code, redirectURI, verifier string) url.Values {
	v := url.Values{}
	v.Set("grant_type", "authorization_code")
	v.Set("client_id", clientID)
	v.Set("client_secret", "s")
	v.Set("code", code)
	v.Set("redirect_uri", redirectURI)
	v.Set("code_verifier", verifier)
	return v
}

// ---- Tests ----

func TestToken_AuthCodeHappyPath_IssuesAccessAndIDTokens(t *testing.T) {
	env := NewTestEnv(t)
	bootstrapKey(t, env)
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")
	cookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse42!")

	const redirect = "https://rp.example.com/cb"
	clientID := seedTokenClient(t, env, redirect, []string{"openid", "profile"})
	verifier, challenge := pkceParams()
	code := runAuthorizeAndGetCode(t, env, cookie, clientID, redirect, "openid profile", verifier, challenge)

	params := buildTokenParams(clientID, code, redirect, verifier)
	rec := doTokenRequest(t, env, params)

	assertCacheControlNoStore(t, rec)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d body=%s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	accessTok, _ := resp["access_token"].(string)
	idTok, _ := resp["id_token"].(string)
	tokenType, _ := resp["token_type"].(string)
	expiresIn, _ := resp["expires_in"].(float64)
	scope, _ := resp["scope"].(string)

	if accessTok == "" {
		t.Fatal("access_token missing")
	}
	if idTok == "" {
		t.Fatal("id_token missing")
	}
	if tokenType != "Bearer" {
		t.Fatalf("token_type=%q want Bearer", tokenType)
	}
	if expiresIn != 900 {
		t.Fatalf("expires_in=%.0f want 900", expiresIn)
	}
	if !strings.Contains(scope, "openid") {
		t.Fatalf("scope=%q should contain openid", scope)
	}
	if _, hasRefresh := resp["refresh_token"]; hasRefresh {
		t.Fatal("refresh_token should be absent (no offline_access scope)")
	}

	// Verify access token signature against the JWKS.
	keyStore := signingkeys.NewStore()
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
		t.Fatalf("verify access token: %v", err)
	}
	userID := env.GetUserIDByEmail(t, "admin@example.com")
	if claims.Subject != userID.String() {
		t.Fatalf("sub=%q want %q", claims.Subject, userID.String())
	}

	// Verify audit row.
	if n := countAuditRows(t, env, "oidc.code.exchanged", "success"); n != 1 {
		t.Fatalf("expected 1 oidc.code.exchanged audit row, got %d", n)
	}
}

func TestToken_AuthCodeWithOfflineAccess_IssuesRefreshToken(t *testing.T) {
	env := NewTestEnv(t)
	bootstrapKey(t, env)
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")
	cookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse42!")

	const redirect = "https://rp.example.com/cb"
	clientID := seedTokenClient(t, env, redirect, []string{"openid", "profile", "offline_access"})
	verifier, challenge := pkceParams()
	code := runAuthorizeAndGetCode(t, env, cookie, clientID, redirect, "openid profile offline_access", verifier, challenge)

	params := buildTokenParams(clientID, code, redirect, verifier)
	rec := doTokenRequest(t, env, params)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d body=%s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	refreshTok, ok := resp["refresh_token"].(string)
	if !ok || refreshTok == "" {
		t.Fatal("refresh_token missing in response")
	}

	// Verify the refresh token exists in Valkey with the right family_id.
	refreshStore := oidc.NewRefreshStore(env.ValkeyClient)
	payload, err := refreshStore.Get(context.Background(), refreshTok)
	if err != nil {
		t.Fatalf("get refresh from valkey: %v", err)
	}
	if payload.UserID == "" {
		t.Fatal("refresh payload user_id empty")
	}

	// Check family_id matches the audit row.
	var familyIDStr string
	err = env.Pool.QueryRow(context.Background(), `
		SELECT metadata->>'family_id'
		FROM audit_logs
		WHERE event_type = 'oidc.code.exchanged' AND outcome = 'success'
	`).Scan(&familyIDStr)
	if err != nil {
		t.Fatalf("read family_id from audit: %v", err)
	}
	if payload.FamilyID != familyIDStr {
		t.Fatalf("refresh family_id=%q want %q", payload.FamilyID, familyIDStr)
	}
}

func TestToken_AuthCodeWithoutOfflineAccess_OmitsRefresh(t *testing.T) {
	env := NewTestEnv(t)
	bootstrapKey(t, env)
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")
	cookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse42!")

	const redirect = "https://rp.example.com/cb"
	clientID := seedTokenClient(t, env, redirect, []string{"openid", "profile"})
	verifier, challenge := pkceParams()
	code := runAuthorizeAndGetCode(t, env, cookie, clientID, redirect, "openid profile", verifier, challenge)

	params := buildTokenParams(clientID, code, redirect, verifier)
	rec := doTokenRequest(t, env, params)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if rt, ok := resp["refresh_token"]; ok && rt != "" {
		t.Fatalf("refresh_token should be absent without offline_access, got %v", rt)
	}
}

func TestToken_MissingClientCredentials_401InvalidClient(t *testing.T) {
	env := NewTestEnv(t)
	bootstrapKey(t, env)

	params := url.Values{}
	params.Set("grant_type", "authorization_code")
	params.Set("code", "some-code")
	params.Set("redirect_uri", "https://rp.example.com/cb")
	params.Set("code_verifier", "verifier")
	// Deliberately no client_id or client_secret.

	rec := doTokenRequest(t, env, params)
	assertCacheControlNoStore(t, rec)
	assertTokenError(t, rec, http.StatusUnauthorized, "invalid_client")
}

func TestToken_WrongClientSecret_401InvalidClient(t *testing.T) {
	env := NewTestEnv(t)
	bootstrapKey(t, env)

	const redirect = "https://rp.example.com/cb"
	clientID := seedTokenClient(t, env, redirect, []string{"openid"})

	params := url.Values{}
	params.Set("grant_type", "authorization_code")
	params.Set("client_id", clientID)
	params.Set("client_secret", "wrong-secret")
	params.Set("code", "irrelevant")
	params.Set("redirect_uri", redirect)
	params.Set("code_verifier", "irrelevant")

	rec := doTokenRequest(t, env, params)
	assertTokenError(t, rec, http.StatusUnauthorized, "invalid_client")

	if n := countAuditRows(t, env, "oidc.client.auth_failed", "failure"); n != 1 {
		t.Fatalf("expected 1 oidc.client.auth_failed audit row, got %d", n)
	}
}

func TestToken_MissingGrantType_400UnsupportedGrantType(t *testing.T) {
	env := NewTestEnv(t)

	params := url.Values{}
	// No grant_type.
	params.Set("client_id", "irrelevant")
	params.Set("client_secret", "irrelevant")

	rec := doTokenRequest(t, env, params)
	assertTokenError(t, rec, http.StatusBadRequest, "unsupported_grant_type")
}

func TestToken_UnknownGrantType_400UnsupportedGrantType(t *testing.T) {
	env := NewTestEnv(t)

	params := url.Values{}
	params.Set("grant_type", "client_credentials")
	params.Set("client_id", "irrelevant")
	params.Set("client_secret", "irrelevant")

	rec := doTokenRequest(t, env, params)
	assertTokenError(t, rec, http.StatusBadRequest, "unsupported_grant_type")
}

func TestToken_ReusedCode_RevokeFamily_400InvalidGrant(t *testing.T) {
	env := NewTestEnv(t)
	bootstrapKey(t, env)
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")
	cookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse42!")

	const redirect = "https://rp.example.com/cb"
	clientID := seedTokenClient(t, env, redirect, []string{"openid", "profile", "offline_access"})
	verifier, challenge := pkceParams()
	code := runAuthorizeAndGetCode(t, env, cookie, clientID, redirect, "openid profile offline_access", verifier, challenge)

	// First exchange — succeeds, mints refresh.
	params := buildTokenParams(clientID, code, redirect, verifier)
	rec1 := doTokenRequest(t, env, params)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first exchange: expected 200 got %d body=%s", rec1.Code, rec1.Body.String())
	}
	var resp1 map[string]any
	_ = json.NewDecoder(rec1.Body).Decode(&resp1)
	refreshTok, _ := resp1["refresh_token"].(string)
	if refreshTok == "" {
		t.Fatal("expected refresh_token in first exchange")
	}

	// Confirm refresh exists in Valkey before replay.
	refreshStore := oidc.NewRefreshStore(env.ValkeyClient)
	if _, err := refreshStore.Get(context.Background(), refreshTok); err != nil {
		t.Fatalf("refresh should exist before replay: %v", err)
	}

	// Second exchange with same code — must be rejected.
	rec2 := doTokenRequest(t, env, params)
	assertTokenError(t, rec2, http.StatusBadRequest, "invalid_grant")

	// Refresh token must be revoked from Valkey.
	if _, err := refreshStore.Get(context.Background(), refreshTok); err == nil {
		t.Fatal("refresh token should have been revoked after code replay")
	}

	// Audit row for replay.
	if n := countAuditRows(t, env, "oidc.code.replay_detected", "failure"); n != 1 {
		t.Fatalf("expected 1 oidc.code.replay_detected audit row, got %d", n)
	}

	// Check family_id in audit matches the one from the original exchange.
	var replayFamilyID string
	if err := env.Pool.QueryRow(context.Background(), `
		SELECT metadata->>'family_id'
		FROM audit_logs
		WHERE event_type = 'oidc.code.replay_detected'
	`).Scan(&replayFamilyID); err != nil {
		t.Fatalf("read replay family_id: %v", err)
	}
	if replayFamilyID == "" {
		t.Fatal("replay audit row missing family_id")
	}
}

func TestToken_ClientMismatch_400InvalidGrant(t *testing.T) {
	env := NewTestEnv(t)
	bootstrapKey(t, env)
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")
	cookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse42!")

	const redirect = "https://rp.example.com/cb"
	// Seed two separate clients.
	clientA := seedTokenClient(t, env, redirect, []string{"openid", "profile"})
	clientB := seedTokenClient(t, env, redirect, []string{"openid", "profile"})

	verifier, challenge := pkceParams()
	// Authorize with client A.
	code := runAuthorizeAndGetCode(t, env, cookie, clientA, redirect, "openid profile", verifier, challenge)

	// Try to exchange with client B's credentials.
	params := url.Values{}
	params.Set("grant_type", "authorization_code")
	params.Set("client_id", clientB)
	params.Set("client_secret", "s")
	params.Set("code", code)
	params.Set("redirect_uri", redirect)
	params.Set("code_verifier", verifier)

	rec := doTokenRequest(t, env, params)
	assertTokenError(t, rec, http.StatusBadRequest, "invalid_grant")
}

func TestToken_RedirectURIMismatch_400InvalidGrant(t *testing.T) {
	env := NewTestEnv(t)
	bootstrapKey(t, env)
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")
	cookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse42!")

	const redirect = "https://rp.example.com/cb"
	clientID := seedTokenClient(t, env, redirect, []string{"openid", "profile"})
	verifier, challenge := pkceParams()
	code := runAuthorizeAndGetCode(t, env, cookie, clientID, redirect, "openid profile", verifier, challenge)

	params := buildTokenParams(clientID, code, "https://different.example.com/cb", verifier)
	rec := doTokenRequest(t, env, params)
	assertTokenError(t, rec, http.StatusBadRequest, "invalid_grant")
}

func TestToken_PKCEMismatch_400InvalidGrant(t *testing.T) {
	env := NewTestEnv(t)
	bootstrapKey(t, env)
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")
	cookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse42!")

	const redirect = "https://rp.example.com/cb"
	clientID := seedTokenClient(t, env, redirect, []string{"openid", "profile"})
	verifier, challenge := pkceParams()
	code := runAuthorizeAndGetCode(t, env, cookie, clientID, redirect, "openid profile", verifier, challenge)

	// Wrong verifier.
	params := buildTokenParams(clientID, code, redirect, "wrong-verifier-that-does-not-match-challenge")
	rec := doTokenRequest(t, env, params)
	assertTokenError(t, rec, http.StatusBadRequest, "invalid_grant")
}

func TestToken_DisabledUser_400InvalidGrant(t *testing.T) {
	env := NewTestEnv(t)
	bootstrapKey(t, env)
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")
	cookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse42!")

	const redirect = "https://rp.example.com/cb"
	clientID := seedTokenClient(t, env, redirect, []string{"openid", "profile"})
	verifier, challenge := pkceParams()
	code := runAuthorizeAndGetCode(t, env, cookie, clientID, redirect, "openid profile", verifier, challenge)

	// Disable the admin user between /authorize and /token.
	userID := env.GetUserIDByEmail(t, "admin@example.com")
	if _, err := env.Pool.Exec(context.Background(),
		`UPDATE users SET status='disabled' WHERE id=$1`, userID,
	); err != nil {
		t.Fatalf("disable user: %v", err)
	}

	params := buildTokenParams(clientID, code, redirect, verifier)
	rec := doTokenRequest(t, env, params)
	assertTokenError(t, rec, http.StatusBadRequest, "invalid_grant")

	if n := countAuditRows(t, env, "oidc.code.user_disabled", "failure"); n != 1 {
		t.Fatalf("expected 1 oidc.code.user_disabled audit row, got %d", n)
	}
}

func TestToken_ExpiredCode_400InvalidGrant(t *testing.T) {
	env := NewTestEnv(t)
	bootstrapKey(t, env)
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")
	cookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse42!")

	const redirect = "https://rp.example.com/cb"
	clientID := seedTokenClient(t, env, redirect, []string{"openid", "profile"})
	verifier, challenge := pkceParams()
	code := runAuthorizeAndGetCode(t, env, cookie, clientID, redirect, "openid profile", verifier, challenge)

	// Force the code to be expired by back-dating expires_at.
	codeHash := sha256hex(code)
	if _, err := env.Pool.Exec(context.Background(),
		`UPDATE authorization_codes SET expires_at = now() - interval '1 minute' WHERE code_hash = $1`,
		codeHash,
	); err != nil {
		t.Fatalf("expire code: %v", err)
	}

	params := buildTokenParams(clientID, code, redirect, verifier)
	rec := doTokenRequest(t, env, params)
	assertTokenError(t, rec, http.StatusBadRequest, "invalid_grant")
}

func TestToken_RateLimitExceeded_429(t *testing.T) {
	const lowLimit = int64(3)
	const redirect = "https://rp.example.com/cb"

	// Rebuild the router with a low TokenRateLimit so we can trigger 429 quickly.
	env := NewTestEnv(t)
	bootstrapKey(t, env)
	deps := env.BuildDeps()
	deps.TokenRateLimit = lowLimit
	router, err := server.BuildRouter(deps)
	if err != nil {
		t.Fatalf("build router with low token rate limit: %v", err)
	}
	env.Router = router

	clientID := seedTokenClient(t, env, redirect, []string{"openid"})

	// Fire lowLimit+1 requests with bad code (avoids expensive signing path).
	// All will hit the same client_id-keyed counter.
	var last *httptest.ResponseRecorder
	for i := 0; i <= int(lowLimit); i++ {
		params := url.Values{}
		params.Set("grant_type", "authorization_code")
		params.Set("client_id", clientID)
		params.Set("client_secret", "s")
		params.Set("code", fmt.Sprintf("bad-code-%d", i))
		params.Set("redirect_uri", redirect)
		params.Set("code_verifier", "some-verifier")

		req := httptest.NewRequestWithContext(
			t.Context(), "POST", "/token",
			strings.NewReader(params.Encode()),
		)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		env.Router.ServeHTTP(rec, req)
		last = rec
	}

	// The (lowLimit+1)th request should be rate-limited.
	if last.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on request %d, got %d body=%s", lowLimit+1, last.Code, last.Body.String())
	}
	assertTokenError(t, last, http.StatusTooManyRequests, "invalid_request")
}
