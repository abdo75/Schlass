package crypto_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/schlass/schlass/internal/crypto"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := testKey(t)
	plaintext := []byte("sensitive-smtp-password")

	ciphertext, err := crypto.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := crypto.Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("round-trip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptProducesDifferentCiphertexts(t *testing.T) {
	key := testKey(t)
	plaintext := []byte("same-input")

	c1, _ := crypto.Encrypt(plaintext, key)
	c2, _ := crypto.Encrypt(plaintext, key)

	if bytes.Equal(c1, c2) {
		t.Fatal("two encryptions of the same plaintext should produce different ciphertexts (unique nonce)")
	}
}

func TestDecryptDetectsTampering(t *testing.T) {
	key := testKey(t)
	ciphertext, _ := crypto.Encrypt([]byte("original"), key)

	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[len(tampered)-1] ^= 0xff

	_, err := crypto.Decrypt(tampered, key)
	if err == nil {
		t.Fatal("expected error when decrypting tampered ciphertext")
	}
}

func TestDecryptWithWrongKeyFails(t *testing.T) {
	key1 := testKey(t)
	key2 := testKey(t)

	ciphertext, _ := crypto.Encrypt([]byte("secret"), key1)

	_, err := crypto.Decrypt(ciphertext, key2)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong key")
	}
}

func TestEncryptRejectsInvalidKeyLength(t *testing.T) {
	_, err := crypto.Encrypt([]byte("data"), []byte("short-key"))
	if err == nil {
		t.Fatal("expected error for invalid key length")
	}
}
