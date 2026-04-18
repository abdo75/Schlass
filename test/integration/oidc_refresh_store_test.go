//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/abdo75/Schlass/internal/oidc"
)

func TestRefreshStore_CreateConsumeRoundTrip(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()
	s := oidc.NewRefreshStore(env.ValkeyClient)

	payload := oidc.RefreshPayload{
		UserID:    uuid.NewString(),
		ClientID:  uuid.NewString(),
		Scopes:    []string{"openid", "offline_access"},
		FamilyID:  uuid.NewString(),
		CreatedAt: time.Now().Unix(),
		Expires:   time.Now().Add(24 * time.Hour).Unix(),
	}
	token, err := s.Create(ctx, payload)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if token == "" {
		t.Fatal("empty token")
	}

	got, err := s.Consume(ctx, token)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if got.UserID != payload.UserID {
		t.Fatal("user_id mismatch")
	}
	if got.FamilyID != payload.FamilyID {
		t.Fatal("family_id mismatch")
	}

	// Reuse detection: mark used, consume again, expect error + payload.
	if err := s.MarkUsed(ctx, token); err != nil {
		t.Fatalf("mark used: %v", err)
	}
	got2, err := s.Consume(ctx, token)
	if err != oidc.ErrRefreshReuseDetected {
		t.Fatalf("expected ErrRefreshReuseDetected, got %v", err)
	}
	if got2 == nil || got2.FamilyID != payload.FamilyID {
		t.Fatal("reuse path must return payload so caller can revoke family")
	}
}

func TestRefreshStore_UnknownTokenReturnsErr(t *testing.T) {
	env := NewTestEnv(t)
	s := oidc.NewRefreshStore(env.ValkeyClient)
	_, err := s.Consume(context.Background(), "never-issued-token")
	if err != oidc.ErrRefreshUnknownOrExpired {
		t.Fatalf("want ErrRefreshUnknownOrExpired, got %v", err)
	}
}

func TestRefreshStore_RevokeFamilyDeletesAllMembers(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()
	s := oidc.NewRefreshStore(env.ValkeyClient)

	family := uuid.NewString()
	var tokens []string
	for i := 0; i < 3; i++ {
		tok, err := s.Create(ctx, oidc.RefreshPayload{
			UserID:    "u",
			ClientID:  "c",
			Scopes:    []string{"openid", "offline_access"},
			FamilyID:  family,
			CreatedAt: time.Now().Unix(),
			Expires:   time.Now().Add(24 * time.Hour).Unix(),
		})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		tokens = append(tokens, tok)
	}

	if err := s.RevokeFamily(ctx, family); err != nil {
		t.Fatalf("revoke family: %v", err)
	}

	for i, tok := range tokens {
		if _, err := s.Consume(ctx, tok); err != oidc.ErrRefreshUnknownOrExpired {
			t.Fatalf("token %d: want ErrRefreshUnknownOrExpired, got %v", i, err)
		}
	}

	// Family SET key gone.
	if n, _ := env.ValkeyClient.Exists(ctx, "oidc:refresh:family:"+family).Result(); n != 0 {
		t.Fatalf("family SET still exists (Exists=%d)", n)
	}
}

func TestRefreshStore_ExpiresRespectsTTL(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()
	s := oidc.NewRefreshStore(env.ValkeyClient)

	// A token that expires in 2 seconds.
	payload := oidc.RefreshPayload{
		UserID:    "u",
		ClientID:  "c",
		FamilyID:  uuid.NewString(),
		Scopes:    []string{"openid"},
		CreatedAt: time.Now().Unix(),
		Expires:   time.Now().Add(2 * time.Second).Unix(),
	}
	token, _ := s.Create(ctx, payload)

	// TTL on the key should be ~2 seconds.
	hash := sha256hexForTest(token)
	ttl, _ := env.ValkeyClient.TTL(ctx, "oidc:refresh:"+hash).Result()
	if ttl > 2*time.Second+200*time.Millisecond || ttl < time.Second {
		t.Fatalf("unexpected ttl: %v", ttl)
	}
}

func TestRefreshStore_CreateRefusesAlreadyExpired(t *testing.T) {
	env := NewTestEnv(t)
	s := oidc.NewRefreshStore(env.ValkeyClient)
	_, err := s.Create(context.Background(), oidc.RefreshPayload{
		UserID:    "u",
		ClientID:  "c",
		FamilyID:  uuid.NewString(),
		Scopes:    []string{"openid"},
		CreatedAt: time.Now().Unix(),
		Expires:   time.Now().Add(-1 * time.Second).Unix(),
	})
	if err == nil {
		t.Fatal("create with past exp must fail")
	}
}

// sha256hexForTest mirrors the package-internal sha256hexStr — used only to
// construct the raw Valkey key in the TTL assertion above.
func sha256hexForTest(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
