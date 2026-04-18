package crypto_test

import (
	"regexp"
	"testing"

	"github.com/abdo75/Schlass/internal/crypto"
)

func TestGenerateRecoveryCodes_Count(t *testing.T) {
	plaintext, hashes, err := crypto.GenerateRecoveryCodes()
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}
	if len(plaintext) != 10 {
		t.Fatalf("want 10 plaintext codes, got %d", len(plaintext))
	}
	if len(hashes) != 10 {
		t.Fatalf("want 10 hashes, got %d", len(hashes))
	}
}

func TestGenerateRecoveryCodes_Format(t *testing.T) {
	plaintext, _, err := crypto.GenerateRecoveryCodes()
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}
	// Format: XXXX-XXXX, 8 alphanumeric chars + dash, from the base58-minus-
	// ambiguous alphabet (no 0/O/I/l/1).
	pattern := regexp.MustCompile(`^[23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{4}-[23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{4}$`)
	for i, code := range plaintext {
		if !pattern.MatchString(code) {
			t.Errorf("code %d %q does not match expected format", i, code)
		}
	}
}

func TestGenerateRecoveryCodes_Unique(t *testing.T) {
	plaintext, _, err := crypto.GenerateRecoveryCodes()
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}
	seen := make(map[string]bool)
	for _, c := range plaintext {
		if seen[c] {
			t.Fatalf("duplicate code in a single batch: %q", c)
		}
		seen[c] = true
	}
}

func TestGenerateRecoveryCodes_HashVerifyRoundTrip(t *testing.T) {
	plaintext, hashes, err := crypto.GenerateRecoveryCodes()
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}
	// Every plaintext code should verify against its own hash and not
	// against another code's hash.
	for i, code := range plaintext {
		ok, err := crypto.VerifyPassword(code, hashes[i])
		if err != nil {
			t.Fatalf("VerifyPassword code %d: %v", i, err)
		}
		if !ok {
			t.Errorf("code %d %q failed to verify against its own hash", i, code)
		}
	}
	// Cross-match: code 0 should NOT verify against hash 1.
	ok, err := crypto.VerifyPassword(plaintext[0], hashes[1])
	if err != nil {
		t.Fatalf("cross-verify error: %v", err)
	}
	if ok {
		t.Fatal("code 0 unexpectedly verified against hash 1 — hash collision or bug")
	}
}
