//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/abdo75/Schlass/internal/server"
)

// rebuildRouterWithRateLimits rebuilds the test router with the supplied
// per-endpoint overrides for the new OIDC rate limiters while leaving the
// generous login/mfa defaults from BuildDeps() in place. Mirrors the
// rebuild-and-scope-via-Cleanup pattern used by WithFakeAuditStore.
func rebuildRouterWithRateLimits(t *testing.T, env *TestEnv, authorizeLimit, userinfoLimit int64) {
	t.Helper()
	original := env.Router
	deps := env.BuildDeps()
	deps.AuthorizeRateLimit = authorizeLimit
	deps.UserinfoRateLimit = userinfoLimit
	newRouter, err := server.BuildRouter(deps)
	if err != nil {
		t.Fatalf("rebuild router with rate-limit overrides: %v", err)
	}
	env.Router = newRouter
	t.Cleanup(func() { env.Router = original })
}

// TestAuthorizeRateLimit_429 asserts GET /authorize trips 429 after the
// per-IP cap is exceeded and that the 429 response carries Retry-After.
// Rate limiting runs BEFORE the /authorize handler logic, so any non-429
// status (400/302/etc.) still counts as "allowed" from the limiter's POV.
func TestAuthorizeRateLimit_429(t *testing.T) {
	env := NewTestEnv(t)
	rebuildRouterWithRateLimits(t, env, 3, 10000)

	var got429 bool
	var lastStatus int
	var retryAfter string
	for i := 0; i < 8; i++ {
		req := httptest.NewRequestWithContext(t.Context(), "GET", "/authorize", nil)
		rec := httptest.NewRecorder()
		env.Router.ServeHTTP(rec, req)
		lastStatus = rec.Code
		if rec.Code == http.StatusTooManyRequests {
			got429 = true
			retryAfter = rec.Header().Get("Retry-After")
			break
		}
	}
	if !got429 {
		t.Fatalf("expected at least one 429 within 8 requests at limit=3 (last status=%d)", lastStatus)
	}
	if retryAfter == "" {
		t.Errorf("429 response missing Retry-After header")
	}
}

// TestUserinfoRateLimit_429 asserts GET /userinfo trips 429 after the per-IP
// cap is exceeded even when the Bearer token itself is valid. The limiter
// sits OUTSIDE BearerAuth so the 429 is returned before the access token is
// parsed — which is the point: a bursty attacker can't amortise away the
// BearerAuth crypto cost by flooding the endpoint.
func TestUserinfoRateLimit_429(t *testing.T) {
	env := NewTestEnv(t)
	bootstrapKey(t, env)
	rebuildRouterWithRateLimits(t, env, 10000, 3)

	env.SeedAdmin(t, "rl@example.com", "CorrectHorse1Battery")
	cookie := env.LoginAsAdmin(t, "rl@example.com", "CorrectHorse1Battery")

	const redirect = "https://rp.example.com/cb"
	clientID := seedTokenClient(t, env, redirect, []string{"openid", "profile", "email"})
	verifier, challenge := pkceParams()
	code := runAuthorizeAndGetCode(t, env, cookie, clientID, redirect, "openid profile email", verifier, challenge)
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

	var got429 bool
	var lastStatus int
	var retryAfter string
	for i := 0; i < 8; i++ {
		req := httptest.NewRequestWithContext(t.Context(), "GET", "/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)
		rec := httptest.NewRecorder()
		env.Router.ServeHTTP(rec, req)
		lastStatus = rec.Code
		if rec.Code == http.StatusTooManyRequests {
			got429 = true
			retryAfter = rec.Header().Get("Retry-After")
			break
		}
	}
	if !got429 {
		t.Fatalf("expected at least one 429 within 8 requests at limit=3 (last status=%d)", lastStatus)
	}
	if retryAfter == "" {
		t.Errorf("429 response missing Retry-After header")
	}
}
