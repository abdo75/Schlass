package crypto_test

import (
	"strings"
	"testing"

	"github.com/abdo75/Schlass/internal/crypto"
)

func TestHashPasswordProducesPHCFormat(t *testing.T) {
	hash, err := crypto.HashPassword("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("hash should start with $argon2id$, got: %s", hash)
	}

	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		t.Fatalf("expected 6 parts in PHC format, got %d: %s", len(parts), hash)
	}
}

func TestHashPasswordProducesUniqueSalts(t *testing.T) {
	h1, _ := crypto.HashPassword("same-password")
	h2, _ := crypto.HashPassword("same-password")

	if h1 == h2 {
		t.Fatal("two hashes of the same password should differ (unique salts)")
	}
}

func TestVerifyPasswordCorrect(t *testing.T) {
	hash, _ := crypto.HashPassword("my-secure-password")

	ok, err := crypto.VerifyPassword("my-secure-password", hash)
	if err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}
	if !ok {
		t.Fatal("expected verification to succeed for correct password")
	}
}

func TestVerifyPasswordWrong(t *testing.T) {
	hash, _ := crypto.HashPassword("my-secure-password")

	ok, err := crypto.VerifyPassword("wrong-password", hash)
	if err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}
	if ok {
		t.Fatal("expected verification to fail for wrong password")
	}
}

func TestVerifyPasswordRejectsInvalidHash(t *testing.T) {
	_, err := crypto.VerifyPassword("password", "not-a-valid-hash")
	if err == nil {
		t.Fatal("expected error for invalid hash format")
	}
}
