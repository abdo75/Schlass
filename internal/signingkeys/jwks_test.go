package signingkeys

import (
	"testing"

	"github.com/abdo75/Schlass/internal/oidc"
	"github.com/google/uuid"
)

func TestBuildJWKSet(t *testing.T) {
	pub, _, err := oidc.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keys := []*SigningKey{{
		ID:           uuid.New(),
		PublicKeyPEM: pub,
	}}
	set, err := BuildJWKSet(keys)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(set.Keys))
	}
	if set.Keys[0].Kid != keys[0].ID.String() {
		t.Fatalf("kid=%s want=%s", set.Keys[0].Kid, keys[0].ID.String())
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
