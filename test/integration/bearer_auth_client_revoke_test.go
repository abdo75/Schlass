//go:build integration

package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/abdo75/Schlass/internal/middleware"
	"github.com/abdo75/Schlass/internal/revokebefore"
)

// newBearerProbeWithValkey builds a BearerAuth-wrapped probe that includes the
// Valkey client so revoke_before checks (both user and client) are active.
func newBearerProbeWithValkey(t *testing.T, env *TestEnv) http.Handler {
	t.Helper()
	probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := middleware.BearerAuth(middleware.BearerAuthDeps{
		Pool:      env.Pool,
		UserStore: env.UserStore,
		Issuer:    env.Cfg.SchlassPublicURL,
		Valkey:    env.ValkeyClient,
	})
	return mw(probe)
}

func TestBearerAuth_ClientRevokeBefore(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()

	kid, priv := seedBearerSigningKey(t, env)
	userID := env.SeedAdmin(t, "revoke-client@example.com", "CorrectHorse1Battery")

	// Use a stable client_id (does not need to exist in DB — bearer_auth only
	// validates the user row; client existence is not checked here).
	clientID := uuid.NewString()

	h := newBearerProbeWithValkey(t, env)

	token := mintAccessToken(t, env.Cfg.SchlassPublicURL, userID.String(), clientID, kid, priv, nil)

	// Pre-revoke: 200
	req := httptest.NewRequest("GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("pre-revoke: status %d, body %s", w.Code, w.Body.String())
	}

	// Set the client cutoff — this pushes all existing ATs for this client
	// into the "stale" bucket.
	if err := revokebefore.ClientSetNow(ctx, env.ValkeyClient, clientID); err != nil {
		t.Fatalf("ClientSetNow: %v", err)
	}

	// Post-revoke: same token, same user — must now be 401.
	req = httptest.NewRequest("GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("post-revoke: status %d, want 401, body %s", w.Code, w.Body.String())
	}
}
