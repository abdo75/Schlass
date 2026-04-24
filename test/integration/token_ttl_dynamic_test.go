//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/abdo75/Schlass/internal/oidc"
	signingkeys "github.com/abdo75/Schlass/internal/signingkeys"
)

func tokenLookup(t *testing.T, env *TestEnv) oidc.PublicKeyLookup {
	t.Helper()
	keyStore := signingkeys.NewStore()
	keys, err := keyStore.ListPublishable(context.Background(), env.Pool)
	if err != nil {
		t.Fatalf("list publishable keys: %v", err)
	}
	if len(keys) == 0 {
		t.Fatal("no publishable signing keys")
	}
	return func(kid string) ([]byte, error) {
		for _, k := range keys {
			if k.ID.String() == kid {
				return k.PublicKeyPEM, nil
			}
		}
		return nil, fmt.Errorf("kid not found: %s", kid)
	}
}

func requireTokenSuccess(t *testing.T, rec *http.Response, body []byte) map[string]any {
	t.Helper()
	if rec.StatusCode != http.StatusOK {
		t.Fatalf("token exchange: got %d body=%s", rec.StatusCode, string(body))
	}
	var resp map[string]any
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	return resp
}

func TestTokenTTL_Dynamic(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()

	bootstrapKey(t, env)
	env.SeedAdmin(t, "admin@example.com", "CorrectHorse42!")
	adminCookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse42!")

	const redirect = "https://rp.example.com/cb"
	clientID := seedTokenClient(t, env, redirect, []string{"openid", "profile", "email", "offline_access"})
	lookup := tokenLookup(t, env)

	exchange := func(scope string) (map[string]any, *oidc.RefreshPayload) {
		t.Helper()
		verifier, challenge := pkceParams()
		code := runAuthorizeAndGetCode(t, env, adminCookie, clientID, redirect, scope, verifier, challenge)
		rec := doTokenRequest(t, env, buildTokenParams(clientID, code, redirect, verifier))
		resp := requireTokenSuccess(t, rec.Result(), rec.Body.Bytes())
		refreshToken, _ := resp["refresh_token"].(string)
		if refreshToken == "" {
			t.Fatal("refresh_token missing in auth_code response")
		}
		return resp, peekRefreshPayload(t, env, refreshToken)
	}

	assertTTLs := func(resp map[string]any, refreshPayload *oidc.RefreshPayload, wantAccessSecs, wantRefreshSecs int64) {
		t.Helper()
		expiresIn, _ := resp["expires_in"].(float64)
		if int64(expiresIn) != wantAccessSecs {
			t.Fatalf("expires_in=%v want %d", resp["expires_in"], wantAccessSecs)
		}

		accessToken, _ := resp["access_token"].(string)
		accessClaims, err := oidc.ParseAndVerifyAccessToken(accessToken, lookup)
		if err != nil {
			t.Fatalf("verify access token: %v", err)
		}
		if got := accessClaims.Expires - accessClaims.IssuedAt; got != wantAccessSecs {
			t.Fatalf("access token ttl=%d want %d", got, wantAccessSecs)
		}

		idToken, _ := resp["id_token"].(string)
		idClaims, err := oidc.ParseAndVerifyIDToken(idToken, lookup)
		if err != nil {
			t.Fatalf("verify id token: %v", err)
		}
		if got := idClaims.Expires - idClaims.IssuedAt; got != wantAccessSecs {
			t.Fatalf("id token ttl=%d want %d", got, wantAccessSecs)
		}

		if got := refreshPayload.Expires - refreshPayload.CreatedAt; got != wantRefreshSecs {
			t.Fatalf("refresh ttl=%d want %d", got, wantRefreshSecs)
		}
	}

	respDefault, refreshDefault := exchange("openid profile email offline_access")
	assertTTLs(respDefault, refreshDefault, 900, 86400)

	body, _ := json.Marshal(map[string]any{
		"access_token_ttl_secs":  600,
		"refresh_token_ttl_secs": 7200,
	})
	rec := adminPatch(t, env, adminCookie, "/api/settings/tokens", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch token ttl settings: got %d body=%s", rec.Code, rec.Body.String())
	}

	respCustom, refreshOriginal := exchange("openid profile email offline_access")
	assertTTLs(respCustom, refreshOriginal, 600, 7200)

	originalRefreshToken, _ := respCustom["refresh_token"].(string)
	refreshRec := doRefreshRequest(t, env, clientID, "s", originalRefreshToken)
	refreshResp := requireTokenSuccess(t, refreshRec.Result(), refreshRec.Body.Bytes())
	rotatedRefreshToken, _ := refreshResp["refresh_token"].(string)
	if rotatedRefreshToken == "" {
		t.Fatal("refresh rotation response missing refresh_token")
	}
	rotatedRefresh := peekRefreshPayload(t, env, rotatedRefreshToken)
	if rotatedRefresh.Expires != refreshOriginal.Expires {
		t.Fatalf("rotated refresh expiry=%d want original %d", rotatedRefresh.Expires, refreshOriginal.Expires)
	}
}
