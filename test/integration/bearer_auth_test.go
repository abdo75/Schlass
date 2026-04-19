//go:build integration

package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/abdo75/Schlass/internal/middleware"
	"github.com/abdo75/Schlass/internal/oidc"
	"github.com/abdo75/Schlass/internal/store"
)

// seedBearerSigningKey bootstraps a fresh signing key and returns its
// published kid + the private PEM so tests can mint tokens that the
// middleware will accept.
func seedBearerSigningKey(t *testing.T, env *TestEnv) (kid string, privPEM []byte) {
	t.Helper()
	pub, priv, err := oidc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("gen keypair: %v", err)
	}
	wrapped, _ := oidc.WrapPrivateKey(priv, env.Cfg.EncryptionKey)
	id, err := store.NewSigningKeyStore().Insert(context.Background(), env.Pool, pub, wrapped, "active")
	if err != nil {
		t.Fatalf("insert key: %v", err)
	}
	return id.String(), priv
}

// newBearerProbe builds a BearerAuth-wrapped handler that records the injected
// user and echoes the token subject via X-Token-Sub for assertions.
// The second return value is a pointer to a pointer, so the caller can read
// the captured user after the request completes.
func newBearerProbe(t *testing.T, env *TestEnv) http.Handler {
	t.Helper()
	probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := middleware.CurrentBearerClaims(r.Context())
		if claims != nil {
			w.Header().Set("X-Token-Sub", claims.Subject)
		}
		w.WriteHeader(http.StatusOK)
	})
	mw := middleware.BearerAuth(middleware.BearerAuthDeps{
		Pool:      env.Pool,
		UserStore: env.UserStore,
		Issuer:    env.Cfg.SchlassPublicURL,
	})
	return mw(probe)
}

// mintAccessToken signs an access token with the given kid and private PEM.
// customize allows individual tests to mutate claims before signing.
func mintAccessToken(t *testing.T, iss, sub, aud, kid string, privPEM []byte, customize func(*oidc.AccessTokenClaims)) string {
	t.Helper()
	now := time.Now()
	c := oidc.AccessTokenClaims{
		Issuer:    iss,
		Subject:   sub,
		Audience:  aud,
		IssuedAt:  now.Unix(),
		NotBefore: now.Unix(),
		Expires:   now.Add(15 * time.Minute).Unix(),
		JTI:       uuid.NewString(),
		Scope:     "openid profile",
	}
	if customize != nil {
		customize(&c)
	}
	signed, err := oidc.SignAccessToken(c, kid, privPEM)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func TestBearerAuth_HappyPath_InjectsUserAndClaims(t *testing.T) {
	env := NewTestEnv(t)
	kid, priv := seedBearerSigningKey(t, env)
	userID := env.SeedAdmin(t, "alice@example.com", "CorrectHorse1Battery")

	h := newBearerProbe(t, env)
	token := mintAccessToken(t, env.Cfg.SchlassPublicURL, userID.String(), uuid.NewString(), kid, priv, nil)

	req := httptest.NewRequestWithContext(t.Context(), "GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-Token-Sub") != userID.String() {
		t.Fatalf("claims not injected: X-Token-Sub=%q", rec.Header().Get("X-Token-Sub"))
	}
}

func TestBearerAuth_MissingHeader_401(t *testing.T) {
	env := NewTestEnv(t)
	seedBearerSigningKey(t, env)
	h := newBearerProbe(t, env)
	req := httptest.NewRequestWithContext(t.Context(), "GET", "/userinfo", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
	if !strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "Bearer ") {
		t.Fatalf("missing WWW-Authenticate: %s", rec.Header().Get("WWW-Authenticate"))
	}
}

func TestBearerAuth_MalformedHeader_401(t *testing.T) {
	env := NewTestEnv(t)
	seedBearerSigningKey(t, env)
	h := newBearerProbe(t, env)
	cases := []string{"NotBearer abc", "Bearer", "Bearer  ", "Basic dXNlcjpwYXNz"}
	for _, hv := range cases {
		req := httptest.NewRequestWithContext(t.Context(), "GET", "/userinfo", nil)
		req.Header.Set("Authorization", hv)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("header=%q: status=%d want 401", hv, rec.Code)
		}
	}
}

func TestBearerAuth_WrongIssuer_401(t *testing.T) {
	env := NewTestEnv(t)
	kid, priv := seedBearerSigningKey(t, env)
	userID := env.SeedAdmin(t, "b@example.com", "CorrectHorse1Battery")
	h := newBearerProbe(t, env)

	token := mintAccessToken(t, "https://attacker.example.com", userID.String(), uuid.NewString(), kid, priv, nil)
	req := httptest.NewRequestWithContext(t.Context(), "GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestBearerAuth_Expired_401(t *testing.T) {
	env := NewTestEnv(t)
	kid, priv := seedBearerSigningKey(t, env)
	userID := env.SeedAdmin(t, "c@example.com", "CorrectHorse1Battery")
	h := newBearerProbe(t, env)

	token := mintAccessToken(t, env.Cfg.SchlassPublicURL, userID.String(), uuid.NewString(), kid, priv, func(c *oidc.AccessTokenClaims) {
		c.Expires = time.Now().Add(-60 * time.Second).Unix()
	})
	req := httptest.NewRequestWithContext(t.Context(), "GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestBearerAuth_TamperedSignature_401(t *testing.T) {
	env := NewTestEnv(t)
	kid, priv := seedBearerSigningKey(t, env)
	userID := env.SeedAdmin(t, "d@example.com", "CorrectHorse1Battery")
	h := newBearerProbe(t, env)

	token := mintAccessToken(t, env.Cfg.SchlassPublicURL, userID.String(), uuid.NewString(), kid, priv, nil)
	// Flip the FIRST char of the signature segment. Base64url's last char
	// encodes only 2 data bits + 4 padding bits, so flipping A↔B at the
	// tail may change only padding — leaving the decoded signature bytes
	// identical and RSA verify succeeding. The first signature char always
	// maps to 6 data bits, so any flip there changes real signature bytes.
	sigStart := strings.LastIndex(token, ".") + 1
	first := token[sigStart]
	var flipped byte
	if first == 'A' {
		flipped = 'B'
	} else {
		flipped = 'A'
	}
	tampered := token[:sigStart] + string(flipped) + token[sigStart+1:]

	req := httptest.NewRequestWithContext(t.Context(), "GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tampered)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestBearerAuth_UnknownKid_401(t *testing.T) {
	env := NewTestEnv(t)
	_, priv := seedBearerSigningKey(t, env)
	userID := env.SeedAdmin(t, "e@example.com", "CorrectHorse1Battery")
	h := newBearerProbe(t, env)

	// Sign with a kid that's not in the store.
	token := mintAccessToken(t, env.Cfg.SchlassPublicURL, userID.String(), uuid.NewString(), "unknown-kid", priv, nil)
	req := httptest.NewRequestWithContext(t.Context(), "GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestBearerAuth_DisabledUser_401(t *testing.T) {
	env := NewTestEnv(t)
	kid, priv := seedBearerSigningKey(t, env)
	userID := env.SeedAdmin(t, "f@example.com", "CorrectHorse1Battery")
	h := newBearerProbe(t, env)

	// Disable user after the token is minted.
	_, _ = env.Pool.Exec(context.Background(), `UPDATE users SET status='disabled' WHERE id=$1`, userID)

	token := mintAccessToken(t, env.Cfg.SchlassPublicURL, userID.String(), uuid.NewString(), kid, priv, nil)
	req := httptest.NewRequestWithContext(t.Context(), "GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("WWW-Authenticate"), "invalid_token") {
		t.Fatalf("WWW-Authenticate missing invalid_token: %s", rec.Header().Get("WWW-Authenticate"))
	}
}

func TestBearerAuth_DeletedUser_401(t *testing.T) {
	env := NewTestEnv(t)
	kid, priv := seedBearerSigningKey(t, env)
	userID := env.SeedAdmin(t, "g@example.com", "CorrectHorse1Battery")
	h := newBearerProbe(t, env)

	_, _ = env.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)

	token := mintAccessToken(t, env.Cfg.SchlassPublicURL, userID.String(), uuid.NewString(), kid, priv, nil)
	req := httptest.NewRequestWithContext(t.Context(), "GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestBearerAuth_EmptyAudience_401(t *testing.T) {
	env := NewTestEnv(t)
	kid, priv := seedBearerSigningKey(t, env)
	userID := env.SeedAdmin(t, "h@example.com", "CorrectHorse1Battery")
	h := newBearerProbe(t, env)

	token := mintAccessToken(t, env.Cfg.SchlassPublicURL, userID.String(), "", kid, priv, nil)
	req := httptest.NewRequestWithContext(t.Context(), "GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
}
