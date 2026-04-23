package oidc

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

func TestPublicPEMToJWK(t *testing.T) {
	pub, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	kid := uuid.New().String()
	jwk, err := PublicPEMToJWK(kid, pub)
	if err != nil {
		t.Fatal(err)
	}
	if jwk.Kty != "RSA" {
		t.Fatalf("kty=%s", jwk.Kty)
	}
	if jwk.Alg != "RS256" {
		t.Fatalf("alg=%s", jwk.Alg)
	}
	if jwk.Use != "sig" {
		t.Fatalf("use=%s", jwk.Use)
	}
	if jwk.Kid != kid {
		t.Fatalf("kid=%s want=%s", jwk.Kid, kid)
	}
	if jwk.N == "" || jwk.E == "" {
		t.Fatal("n/e missing")
	}
	buf, _ := json.Marshal(jwk)
	if len(buf) < 10 {
		t.Fatal("marshal too small")
	}
}
