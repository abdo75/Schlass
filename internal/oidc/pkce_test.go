package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestVerifyPKCE_S256_HappyAndMismatch(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" // RFC 7636 test vector
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	if !VerifyPKCE(challenge, verifier) {
		t.Fatal("correct verifier should match")
	}
	if VerifyPKCE(challenge, "wrong-verifier") {
		t.Fatal("wrong verifier must not match")
	}
	if VerifyPKCE("", verifier) {
		t.Fatal("empty challenge must not match")
	}
	if VerifyPKCE(challenge, "") {
		t.Fatal("empty verifier must not match")
	}
}
