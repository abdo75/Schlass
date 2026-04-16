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

func TestGenerateTemporaryPassword_LengthAndAlphabet(t *testing.T) {
	seen := make(map[string]bool, 128)
	for i := 0; i < 128; i++ {
		pw, err := crypto.GenerateTemporaryPassword()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(pw) != 16 {
			t.Errorf("expected 16 chars, got %d (%q)", len(pw), pw)
		}
		for _, r := range pw {
			switch r {
			case '0', 'O', 'I', 'l', '1':
				t.Errorf("ambiguous character %q in password %q", r, pw)
			}
		}
		if seen[pw] {
			t.Errorf("duplicate password across 128 iterations: %q", pw)
		}
		seen[pw] = true
	}
}

func TestGenerateTemporaryPassword_SatisfiesPolicy(t *testing.T) {
	for i := 0; i < 64; i++ {
		pw, err := crypto.GenerateTemporaryPassword()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(pw) < 12 {
			t.Fatalf("too short: %q", pw)
		}
		var hasUpper, hasDigit bool
		for _, r := range pw {
			if r >= 'A' && r <= 'Z' {
				hasUpper = true
			}
			if r >= '0' && r <= '9' {
				hasDigit = true
			}
		}
		if !hasUpper || !hasDigit {
			t.Errorf("policy violation: %q (upper=%v digit=%v)", pw, hasUpper, hasDigit)
		}
	}
}
