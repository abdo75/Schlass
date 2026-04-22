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

func TestVerifyPasswordRejectsMalformedHashes(t *testing.T) {
	cases := map[string]string{
		"wrong algorithm":     "$argon2i$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaA",
		"unparseable version": "$argon2id$v=foo$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaA",
		"unparseable params":  "$argon2id$v=19$m=bad,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaA",
		"non-b64 salt":        "$argon2id$v=19$m=19456,t=2,p=1$!!!notb64!!!$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaA",
		"non-b64 hash":        "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$!!!notb64!!!",
		"too few parts":       "$argon2id$v=19$m=19456,t=2,p=1$onlyonefield",
		"empty string":        "",
	}
	for name, encoded := range cases {
		t.Run(name, func(t *testing.T) {
			ok, err := crypto.VerifyPassword("password", encoded)
			if err == nil {
				t.Fatalf("expected error, got ok=%v", ok)
			}
			if ok {
				t.Fatalf("expected ok=false on malformed hash")
			}
		})
	}
}

func TestHashPasswordEmbedsExpectedParameters(t *testing.T) {
	hash, err := crypto.HashPassword("anything")
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	const wantPrefix = "$argon2id$v=19$m=19456,t=2,p=1$"
	if !strings.HasPrefix(hash, wantPrefix) {
		t.Fatalf("hash params drifted from constants.\n  want prefix: %s\n  got hash:    %s", wantPrefix, hash)
	}
}

func TestHashAndVerifyEmptyPassword(t *testing.T) {
	hash, err := crypto.HashPassword("")
	if err != nil {
		t.Fatalf("HashPassword(\"\") failed: %v", err)
	}

	ok, err := crypto.VerifyPassword("", hash)
	if err != nil {
		t.Fatalf("VerifyPassword(\"\", hash) failed: %v", err)
	}
	if !ok {
		t.Fatal("empty password should round-trip cleanly")
	}

	ok, err = crypto.VerifyPassword("not-empty", hash)
	if err != nil {
		t.Fatalf("VerifyPassword mismatch failed: %v", err)
	}
	if ok {
		t.Fatal("non-empty password must not match empty-password hash")
	}
}

func BenchmarkHashPassword(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := crypto.HashPassword("benchmark-password"); err != nil {
			b.Fatalf("HashPassword failed: %v", err)
		}
	}
}

func BenchmarkVerifyPassword(b *testing.B) {
	hash, err := crypto.HashPassword("benchmark-password")
	if err != nil {
		b.Fatalf("HashPassword failed: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := crypto.VerifyPassword("benchmark-password", hash); err != nil {
			b.Fatalf("VerifyPassword failed: %v", err)
		}
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
