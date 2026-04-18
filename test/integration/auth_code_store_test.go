//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/abdo75/Schlass/internal/crypto"
	"github.com/abdo75/Schlass/internal/store"
)

// sha256hex produces the code_hash form expected by AuthCodeStore.
func sha256hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// seedOIDCClient creates a test client and returns its ID.
func seedOIDCClient(t *testing.T, env *TestEnv, redirect string) uuid.UUID {
	t.Helper()
	hash, _ := crypto.HashPassword("s")
	var id uuid.UUID
	err := env.Pool.QueryRow(context.Background(), `
		INSERT INTO clients (name, client_type, secret_hash, redirect_uris,
		  allowed_grant_types, allowed_scopes, token_endpoint_auth_method)
		VALUES ('t','confidential',$1,ARRAY[$2::text],
		  ARRAY['authorization_code','refresh_token'],
		  ARRAY['openid','profile','email','offline_access'],
		  'client_secret_post')
		RETURNING id
	`, hash, redirect).Scan(&id)
	if err != nil {
		t.Fatalf("seed client: %v", err)
	}
	return id
}

func TestAuthCodeStore_InsertAndConsumeOnce(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()

	clientID := seedOIDCClient(t, env, "http://localhost/cb")
	userID := env.SeedAdmin(t, "u@example.com", "CorrectHorse1Battery")

	s := store.NewAuthCodeStore()
	code := "raw-code-abc"
	hash := sha256hex(code)
	familyID := uuid.New()
	err := s.Insert(ctx, env.Pool, store.AuthCodeRow{
		CodeHash:            hash,
		ClientID:            clientID,
		UserID:              userID,
		RedirectURI:         "http://localhost/cb",
		Scopes:              []string{"openid", "profile"},
		Nonce:               nil,
		CodeChallenge:       "chal",
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(60 * time.Second),
		FamilyID:            familyID,
	})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	got, err := s.ConsumeOnce(ctx, env.Pool, hash)
	if err != nil {
		t.Fatalf("consume 1: %v", err)
	}
	if got.FamilyID != familyID {
		t.Fatalf("family_id mismatch")
	}
	if got.ClientID != clientID || got.UserID != userID {
		t.Fatalf("client/user mismatch")
	}

	_, err = s.ConsumeOnce(ctx, env.Pool, hash)
	if err != store.ErrAuthCodeAlreadyUsed {
		t.Fatalf("consume 2 err=%v want ErrAuthCodeAlreadyUsed", err)
	}

	fam, err := s.LookupFamilyByCodeHash(ctx, env.Pool, hash)
	if err != nil {
		t.Fatalf("family lookup: %v", err)
	}
	if fam != familyID {
		t.Fatal("family lookup mismatch")
	}
}

func TestAuthCodeStore_ExpiredCodeNotConsumed(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()

	clientID := seedOIDCClient(t, env, "http://localhost/cb")
	userID := env.SeedAdmin(t, "u2@example.com", "CorrectHorse1Battery")
	s := store.NewAuthCodeStore()
	hash := sha256hex("expired-code")
	_ = s.Insert(ctx, env.Pool, store.AuthCodeRow{
		CodeHash:            hash,
		ClientID:            clientID,
		UserID:              userID,
		RedirectURI:         "http://localhost/cb",
		Scopes:              []string{"openid"},
		CodeChallenge:       "chal",
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(-1 * time.Second),
		FamilyID:            uuid.New(),
	})
	_, err := s.ConsumeOnce(ctx, env.Pool, hash)
	if err != store.ErrAuthCodeAlreadyUsed {
		t.Fatalf("expired code should be ErrAuthCodeAlreadyUsed, got %v", err)
	}
}

func TestAuthCodeStore_UnknownCodeReturnsErr(t *testing.T) {
	env := NewTestEnv(t)
	s := store.NewAuthCodeStore()
	_, err := s.ConsumeOnce(context.Background(), env.Pool, "deadbeef"+sha256hex("unknown"))
	if err != store.ErrAuthCodeAlreadyUsed {
		t.Fatalf("want ErrAuthCodeAlreadyUsed, got %v", err)
	}
}

func TestAuthCodeStore_NonceRoundTrip(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()
	clientID := seedOIDCClient(t, env, "http://localhost/cb")
	userID := env.SeedAdmin(t, "u3@example.com", "CorrectHorse1Battery")
	s := store.NewAuthCodeStore()
	nonce := "xyz-123"
	hash := sha256hex("code-w-nonce")
	_ = s.Insert(ctx, env.Pool, store.AuthCodeRow{
		CodeHash:            hash,
		ClientID:            clientID,
		UserID:              userID,
		RedirectURI:         "http://localhost/cb",
		Scopes:              []string{"openid"},
		Nonce:               &nonce,
		CodeChallenge:       "chal",
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(60 * time.Second),
		FamilyID:            uuid.New(),
	})
	got, _ := s.ConsumeOnce(ctx, env.Pool, hash)
	if got.Nonce == nil || *got.Nonce != "xyz-123" {
		t.Fatalf("nonce round-trip failed: %v", got.Nonce)
	}
}
