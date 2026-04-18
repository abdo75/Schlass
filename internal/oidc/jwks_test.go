package oidc

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/abdo75/Schlass/internal/store"
)

func TestBuildJWKSet(t *testing.T) {
	pub, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keys := []*store.SigningKey{{
		ID:           uuid.New(),
		Algorithm:    "RS256",
		PublicKeyPEM: pub,
		Status:       "active",
	}}
	set, err := BuildJWKSet(keys)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(set.Keys))
	}
	k := set.Keys[0]
	if k.Kty != "RSA" {
		t.Fatalf("kty=%s", k.Kty)
	}
	if k.Alg != "RS256" {
		t.Fatalf("alg=%s", k.Alg)
	}
	if k.Use != "sig" {
		t.Fatalf("use=%s", k.Use)
	}
	if k.Kid != keys[0].ID.String() {
		t.Fatalf("kid=%s want=%s", k.Kid, keys[0].ID)
	}
	if k.N == "" || k.E == "" {
		t.Fatal("n/e missing")
	}
	buf, _ := json.Marshal(set)
	if len(buf) < 10 {
		t.Fatal("marshal too small")
	}
}

func TestBuildJWKSet_Empty(t *testing.T) {
	set, err := BuildJWKSet(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 0 {
		t.Fatalf("empty input should yield empty set, got %d", len(set.Keys))
	}
}
