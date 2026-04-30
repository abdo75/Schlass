//go:build integration

package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/abdo75/Schlass/internal/crypto"
)

// seedAuthorizeClient inserts a confidential OIDC client with the given
// redirect URI and allowed scopes. Returns the newly created client ID string.
func seedAuthorizeClient(t *testing.T, env *TestEnv, redirect string, allowedScopes []string) string {
	t.Helper()
	hash, _ := crypto.HashPassword("s")
	var id string
	err := env.Pool.QueryRow(context.Background(), `
		INSERT INTO clients (name, client_type, secret_hash, redirect_uris,
		  allowed_grant_types, allowed_scopes, token_endpoint_auth_method)
		VALUES ('t','confidential',$1,ARRAY[$2::text],
		  ARRAY['authorization_code','refresh_token'],
		  $3::text[],
		  'client_secret_post')
		RETURNING id
	`, hash, redirect, allowedScopes).Scan(&id)
	if err != nil {
		t.Fatalf("seed client: %v", err)
	}
	return id
}

// validAuthorizeURL builds a complete /authorize URL for the given client and redirect.
func validAuthorizeURL(clientID, redirectURI string) string {
	v := url.Values{}
	v.Set("client_id", clientID)
	v.Set("redirect_uri", redirectURI)
	v.Set("response_type", "code")
	v.Set("state", "test-state-abc")
	v.Set("scope", "openid profile")
	v.Set("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
	v.Set("code_challenge_method", "S256")
	return "/authorize?" + v.Encode()
}

// assertLocalError verifies a response redirected to /oidc/error and an audit
// row with the given oauth_error value was written.
func assertLocalError(t *testing.T, env *TestEnv, rec *httptest.ResponseRecorder, oauthError string) string {
	t.Helper()
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302 got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/oidc/error?ref=err_") {
		t.Fatalf("expected redirect to /oidc/error?ref=err_... got %q", loc)
	}

	// Extract correlation ID from the URL.
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse location %q: %v", loc, err)
	}
	corrID := parsed.Query().Get("ref")
	if corrID == "" {
		t.Fatalf("no ref param in %q", loc)
	}

	// Verify audit row. Note: AuditStore.Log merges the HTTP request's
	// correlation ID (UUID) into metadata under "correlation_id", so we use
	// the distinct "error_ref" key for the /oidc/error page ref value.
	var count int
	err = env.Pool.QueryRow(context.Background(), `
		SELECT count(*) FROM audit_logs
		WHERE event_type = 'oidc.authorize.invalid_request'
		  AND outcome = 'failure'
		  AND metadata->>'oauth_error' = $1
		  AND metadata->>'error_ref' = $2
	`, oauthError, corrID).Scan(&count)
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 audit row for oauth_error=%q error_ref=%q, got %d", oauthError, corrID, count)
	}
	return corrID
}

// assertRedirectError verifies the response redirected back to the redirect URI
// with the given error code (and optionally state).
func assertRedirectError(t *testing.T, rec *httptest.ResponseRecorder, redirectURI, errorCode, state string) {
	t.Helper()
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302 got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, redirectURI) {
		t.Fatalf("redirect should start with %q, got %q", redirectURI, loc)
	}
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	qp := parsed.Query()
	if got := qp.Get("error"); got != errorCode {
		t.Fatalf("error=%q want %q (location=%q)", got, errorCode, loc)
	}
	if state != "" {
		if got := qp.Get("state"); got != state {
			t.Fatalf("state=%q want %q", got, state)
		}
	}
}

// doAuthorize fires a GET /authorize request against env.Router.
func doAuthorize(t *testing.T, env *TestEnv, rawURL string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), "GET", rawURL, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	return rec
}

// ---- Tests ----

func TestAuthorize_UnknownClientIDRendersLocalError(t *testing.T) {
	env := NewTestEnv(t)
	randomUUID := "00000000-dead-beef-0000-000000000000"
	rawURL := fmt.Sprintf("/authorize?client_id=%s&redirect_uri=%s&response_type=code&state=s&scope=openid&code_challenge=abc&code_challenge_method=S256",
		randomUUID, url.QueryEscape("https://rp.example.com/cb"))
	rec := doAuthorize(t, env, rawURL, nil)
	assertLocalError(t, env, rec, "invalid_client")
}

func TestAuthorize_MissingClientIDRendersLocalError(t *testing.T) {
	env := NewTestEnv(t)
	rawURL := "/authorize?redirect_uri=" + url.QueryEscape("https://rp.example.com/cb")
	rec := doAuthorize(t, env, rawURL, nil)
	assertLocalError(t, env, rec, "invalid_request")
}

func TestAuthorize_MismatchedRedirectURIRendersLocalError(t *testing.T) {
	env := NewTestEnv(t)
	clientID := seedAuthorizeClient(t, env, "https://rp.example.com/cb", []string{"openid", "profile"})
	rawURL := fmt.Sprintf("/authorize?client_id=%s&redirect_uri=%s&response_type=code&state=s&scope=openid&code_challenge=abc&code_challenge_method=S256",
		clientID, url.QueryEscape("https://evil.example.com/cb"))
	rec := doAuthorize(t, env, rawURL, nil)
	assertLocalError(t, env, rec, "invalid_redirect_uri")
}

func TestAuthorize_DisabledClientRendersLocalError(t *testing.T) {
	env := NewTestEnv(t)
	clientID := seedAuthorizeClient(t, env, "https://rp.example.com/cb", []string{"openid", "profile"})

	// Manually disable the client.
	_, err := env.Pool.Exec(context.Background(), `UPDATE clients SET status='disabled' WHERE id=$1`, clientID)
	if err != nil {
		t.Fatalf("disable client: %v", err)
	}

	rawURL := validAuthorizeURL(clientID, "https://rp.example.com/cb")
	rec := doAuthorize(t, env, rawURL, nil)
	assertLocalError(t, env, rec, "invalid_client")
}

func TestAuthorize_UnsupportedResponseTypeRedirectsToRP(t *testing.T) {
	env := NewTestEnv(t)
	const redirect = "https://rp.example.com/cb"
	clientID := seedAuthorizeClient(t, env, redirect, []string{"openid", "profile"})
	rawURL := fmt.Sprintf("/authorize?client_id=%s&redirect_uri=%s&response_type=token&state=mystate&scope=openid&code_challenge=abc&code_challenge_method=S256",
		clientID, url.QueryEscape(redirect))
	rec := doAuthorize(t, env, rawURL, nil)
	assertRedirectError(t, rec, redirect, "unsupported_response_type", "mystate")
}

func TestAuthorize_MissingStateIsInvalidRequest(t *testing.T) {
	env := NewTestEnv(t)
	const redirect = "https://rp.example.com/cb"
	clientID := seedAuthorizeClient(t, env, redirect, []string{"openid", "profile"})
	rawURL := fmt.Sprintf("/authorize?client_id=%s&redirect_uri=%s&response_type=code&scope=openid&code_challenge=abc&code_challenge_method=S256",
		clientID, url.QueryEscape(redirect))
	rec := doAuthorize(t, env, rawURL, nil)
	assertRedirectError(t, rec, redirect, "invalid_request", "")
}

func TestAuthorize_MissingCodeChallengeIsInvalidRequest(t *testing.T) {
	env := NewTestEnv(t)
	const redirect = "https://rp.example.com/cb"
	clientID := seedAuthorizeClient(t, env, redirect, []string{"openid", "profile"})
	rawURL := fmt.Sprintf("/authorize?client_id=%s&redirect_uri=%s&response_type=code&state=s&scope=openid",
		clientID, url.QueryEscape(redirect))
	rec := doAuthorize(t, env, rawURL, nil)
	assertRedirectError(t, rec, redirect, "invalid_request", "s")

	// Check the error_description.
	parsed, _ := url.Parse(rec.Header().Get("Location"))
	desc := parsed.Query().Get("error_description")
	if !strings.Contains(desc, "PKCE S256") {
		t.Fatalf("expected PKCE S256 in error_description, got %q", desc)
	}
}

func TestAuthorize_ScopeNotSubsetRejected(t *testing.T) {
	env := NewTestEnv(t)
	const redirect = "https://rp.example.com/cb"
	clientID := seedAuthorizeClient(t, env, redirect, []string{"openid", "profile"})
	// offline_access not in allowed_scopes for this client.
	rawURL := fmt.Sprintf("/authorize?client_id=%s&redirect_uri=%s&response_type=code&state=s&scope=openid+profile+offline_access&code_challenge=abc&code_challenge_method=S256",
		clientID, url.QueryEscape(redirect))
	rec := doAuthorize(t, env, rawURL, nil)
	assertRedirectError(t, rec, redirect, "invalid_scope", "s")
}

func TestAuthorize_OpenIDRequired(t *testing.T) {
	env := NewTestEnv(t)
	const redirect = "https://rp.example.com/cb"
	clientID := seedAuthorizeClient(t, env, redirect, []string{"openid", "profile", "email"})
	rawURL := fmt.Sprintf("/authorize?client_id=%s&redirect_uri=%s&response_type=code&state=s&scope=profile+email&code_challenge=abc&code_challenge_method=S256",
		clientID, url.QueryEscape(redirect))
	rec := doAuthorize(t, env, rawURL, nil)
	assertRedirectError(t, rec, redirect, "invalid_scope", "s")
}

func TestAuthorize_AuthedIssuesCodeAndRedirects(t *testing.T) {
	env := NewTestEnv(t)
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")
	cookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse42!")

	const redirect = "https://rp.example.com/cb"
	clientID := seedAuthorizeClient(t, env, redirect, []string{"openid", "profile"})
	rawURL := validAuthorizeURL(clientID, redirect)

	rec := doAuthorize(t, env, rawURL, cookie)
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302 got %d: %s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, redirect) {
		t.Fatalf("redirect should go to RP, got %q", loc)
	}
	parsed, _ := url.Parse(loc)
	qp := parsed.Query()
	code := qp.Get("code")
	if code == "" {
		t.Fatalf("no code in redirect: %q", loc)
	}
	if qp.Get("state") != "test-state-abc" {
		t.Fatalf("state mismatch: %q", qp.Get("state"))
	}

	// Assert authorization_codes row exists.
	var codeCount int
	env.Pool.QueryRow(context.Background(), `SELECT count(*) FROM authorization_codes`).Scan(&codeCount)
	if codeCount != 1 {
		t.Fatalf("expected 1 authorization_codes row, got %d", codeCount)
	}

	// Assert family_id is stamped on the authorization_codes row.
	// (`oidc.authorize.succeeded` is no longer audited — see authorize.go;
	// the equivalent forensic data lands on `oidc.code.exchanged` instead.)
	var familyIDStr string
	err := env.Pool.QueryRow(context.Background(), `
		SELECT family_id::text FROM authorization_codes LIMIT 1
	`).Scan(&familyIDStr)
	if err != nil {
		t.Fatalf("authorization_codes family_id: %v", err)
	}
	if familyIDStr == "" {
		t.Fatal("family_id missing on authorization_codes row")
	}
}

func TestAuthorize_UnauthedRedirectsToLoginWithReturnTo(t *testing.T) {
	env := NewTestEnv(t)
	const redirect = "https://rp.example.com/cb"
	clientID := seedAuthorizeClient(t, env, redirect, []string{"openid", "profile"})
	rawURL := validAuthorizeURL(clientID, redirect)

	rec := doAuthorize(t, env, rawURL, nil) // no cookie
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302 got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/login?return_to=") {
		t.Fatalf("expected /login?return_to=... got %q", loc)
	}
	// The return_to value must contain the /authorize path.
	parsed, _ := url.Parse(loc)
	returnTo, err := url.QueryUnescape(parsed.Query().Get("return_to"))
	if err != nil {
		t.Fatalf("unescape return_to: %v", err)
	}
	if !strings.Contains(returnTo, "/authorize") {
		t.Fatalf("return_to should contain /authorize, got %q", returnTo)
	}
}

func TestAuthorize_PromptNoneUnauthedReturnsLoginRequired(t *testing.T) {
	env := NewTestEnv(t)
	const redirect = "https://rp.example.com/cb"
	clientID := seedAuthorizeClient(t, env, redirect, []string{"openid", "profile"})
	v := url.Values{}
	v.Set("client_id", clientID)
	v.Set("redirect_uri", redirect)
	v.Set("response_type", "code")
	v.Set("state", "s1")
	v.Set("scope", "openid")
	v.Set("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
	v.Set("code_challenge_method", "S256")
	v.Set("prompt", "none")
	rec := doAuthorize(t, env, "/authorize?"+v.Encode(), nil)
	assertRedirectError(t, rec, redirect, "login_required", "s1")
}

func TestAuthorize_PromptLoginClearsSessionAndRedirectsToLogin(t *testing.T) {
	env := NewTestEnv(t)
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")
	cookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse42!")

	const redirect = "https://rp.example.com/cb"
	clientID := seedAuthorizeClient(t, env, redirect, []string{"openid", "profile"})
	v := url.Values{}
	v.Set("client_id", clientID)
	v.Set("redirect_uri", redirect)
	v.Set("response_type", "code")
	v.Set("state", "s2")
	v.Set("scope", "openid")
	v.Set("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
	v.Set("code_challenge_method", "S256")
	v.Set("prompt", "login")
	rec := doAuthorize(t, env, "/authorize?"+v.Encode(), cookie)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302 got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/login?return_to=") {
		t.Fatalf("expected /login redirect got %q", loc)
	}

	// session.reauth_forced audit row must exist.
	var count int
	env.Pool.QueryRow(context.Background(), `
		SELECT count(*) FROM audit_logs WHERE event_type='session.reauth_forced'
	`).Scan(&count)
	if count != 1 {
		t.Fatalf("expected 1 session.reauth_forced audit row, got %d", count)
	}

	// Set-Cookie should clear the session.
	cleared := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == "schlass_session" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("expected Set-Cookie clearing schlass_session")
	}
}

func TestAuthorize_NonceStoredOnRow(t *testing.T) {
	env := NewTestEnv(t)
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")
	cookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse42!")

	const redirect = "https://rp.example.com/cb"
	clientID := seedAuthorizeClient(t, env, redirect, []string{"openid", "profile"})
	v := url.Values{}
	v.Set("client_id", clientID)
	v.Set("redirect_uri", redirect)
	v.Set("response_type", "code")
	v.Set("state", "s3")
	v.Set("scope", "openid")
	v.Set("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
	v.Set("code_challenge_method", "S256")
	v.Set("nonce", "xyz-nonce-value")
	rec := doAuthorize(t, env, "/authorize?"+v.Encode(), cookie)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302 got %d", rec.Code)
	}

	var nonce string
	err := env.Pool.QueryRow(context.Background(), `SELECT nonce FROM authorization_codes`).Scan(&nonce)
	if err != nil {
		t.Fatalf("query nonce: %v", err)
	}
	if nonce != "xyz-nonce-value" {
		t.Fatalf("nonce=%q want 'xyz-nonce-value'", nonce)
	}
}

func TestAuthorize_PromptValueInvalidRejected(t *testing.T) {
	env := NewTestEnv(t)
	const redirect = "https://rp.example.com/cb"
	clientID := seedAuthorizeClient(t, env, redirect, []string{"openid", "profile"})
	v := url.Values{}
	v.Set("client_id", clientID)
	v.Set("redirect_uri", redirect)
	v.Set("response_type", "code")
	v.Set("state", "s4")
	v.Set("scope", "openid")
	v.Set("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
	v.Set("code_challenge_method", "S256")
	v.Set("prompt", "consent") // unsupported
	rec := doAuthorize(t, env, "/authorize?"+v.Encode(), nil)
	assertRedirectError(t, rec, redirect, "invalid_request", "s4")
}

func TestAuthorize_PromptNoneCombinedRejected(t *testing.T) {
	env := NewTestEnv(t)
	const redirect = "https://rp.example.com/cb"
	clientID := seedAuthorizeClient(t, env, redirect, []string{"openid", "profile"})
	// "none login" — combined prompt values.
	rawURL := fmt.Sprintf("/authorize?client_id=%s&redirect_uri=%s&response_type=code&state=s5&scope=openid&code_challenge=abc&code_challenge_method=S256&prompt=%s",
		clientID, url.QueryEscape(redirect), url.QueryEscape("none login"))
	rec := doAuthorize(t, env, rawURL, nil)
	assertRedirectError(t, rec, redirect, "invalid_request", "s5")
}

func TestAuthorize_MaxAgeInvalidRejected(t *testing.T) {
	env := NewTestEnv(t)
	const redirect = "https://rp.example.com/cb"
	clientID := seedAuthorizeClient(t, env, redirect, []string{"openid", "profile"})
	v := url.Values{}
	v.Set("client_id", clientID)
	v.Set("redirect_uri", redirect)
	v.Set("response_type", "code")
	v.Set("state", "s6")
	v.Set("scope", "openid")
	v.Set("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
	v.Set("code_challenge_method", "S256")
	v.Set("max_age", "abc") // non-integer
	rec := doAuthorize(t, env, "/authorize?"+v.Encode(), nil)
	assertRedirectError(t, rec, redirect, "invalid_request", "s6")
}

// (TestAuthorize_AuditMetadataScopesIsJSONArray was removed when we stopped
// emitting `oidc.authorize.succeeded`. The equivalent JSONB-shape coverage
// for OIDC scopes lives on `oidc.code.exchanged` and is exercised by the
// token-exchange tests in oidc_code_exchange_test.go.)
