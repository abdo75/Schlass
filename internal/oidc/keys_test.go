package oidc

import (
	"bytes"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(pub) == 0 || !bytes.Contains(pub, []byte("BEGIN PUBLIC KEY")) {
		t.Fatalf("public PEM malformed: %s", pub)
	}
	if len(priv) == 0 || !bytes.Contains(priv, []byte("BEGIN RSA PRIVATE KEY")) {
		t.Fatalf("private PEM malformed")
	}
}

func TestWrapUnwrapPrivateKey(t *testing.T) {
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i)
	}
	wrapped, err := WrapPrivateKey(priv, kek)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if bytes.Contains(wrapped, priv) {
		t.Fatal("wrapped output contains plaintext")
	}
	unwrapped, err := UnwrapPrivateKey(wrapped, kek)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if !bytes.Equal(priv, unwrapped) {
		t.Fatal("round-trip mismatch")
	}
}

func TestUnwrapWithWrongKEKFails(t *testing.T) {
	_, priv, _ := GenerateKeyPair()
	kek := make([]byte, 32)
	wrapped, _ := WrapPrivateKey(priv, kek)
	wrongKEK := make([]byte, 32)
	wrongKEK[0] = 1
	if _, err := UnwrapPrivateKey(wrapped, wrongKEK); err == nil {
		t.Fatal("unwrap with wrong KEK must fail")
	}
}

func TestParsePrivatePEMRoundTrip(t *testing.T) {
	_, priv, _ := GenerateKeyPair()
	key, err := ParsePrivatePEM(priv)
	if err != nil {
		t.Fatalf("parse priv: %v", err)
	}
	if key == nil || key.N == nil {
		t.Fatal("parsed key malformed")
	}
}

func TestParsePublicPEMRoundTrip(t *testing.T) {
	pub, _, _ := GenerateKeyPair()
	key, err := ParsePublicPEM(pub)
	if err != nil {
		t.Fatalf("parse pub: %v", err)
	}
	if key == nil || key.N == nil {
		t.Fatal("parsed key malformed")
	}
}
