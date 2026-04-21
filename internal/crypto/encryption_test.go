package crypto_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"testing"

	"github.com/abdo75/Schlass/internal/crypto"
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
	aad := []byte("instance_config:smtp_password")
	plaintext := []byte("sensitive-smtp-password")

	ciphertext, err := crypto.Encrypt(plaintext, key, aad)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := crypto.Decrypt(ciphertext, key, aad)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("round-trip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptProducesDifferentCiphertexts(t *testing.T) {
	key := testKey(t)
	aad := []byte("ctx")
	plaintext := []byte("same-input")

	c1, _ := crypto.Encrypt(plaintext, key, aad)
	c2, _ := crypto.Encrypt(plaintext, key, aad)

	if bytes.Equal(c1, c2) {
		t.Fatal("two encryptions of same plaintext must differ (unique DEK + nonces)")
	}
	if bytes.Equal(c1[1:61], c2[1:61]) {
		t.Fatal("wrapped DEK region must differ between encryptions")
	}
}

func TestEncryptV1FormatMarker(t *testing.T) {
	key := testKey(t)
	ct, err := crypto.Encrypt([]byte("x"), key, []byte("ctx"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(ct) == 0 || ct[0] != 0x01 {
		t.Fatalf("expected version byte 0x01, got %#x (len=%d)", ct[0], len(ct))
	}
}

func TestDecryptDetectsTampering(t *testing.T) {
	key := testKey(t)
	aad := []byte("ctx")
	ciphertext, _ := crypto.Encrypt([]byte("original"), key, aad)

	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[len(tampered)-1] ^= 0xff

	if _, err := crypto.Decrypt(tampered, key, aad); err == nil {
		t.Fatal("expected error when decrypting tampered ciphertext")
	}
}

func TestDecryptWithWrongKeyFails(t *testing.T) {
	key1 := testKey(t)
	key2 := testKey(t)
	aad := []byte("ctx")

	ciphertext, _ := crypto.Encrypt([]byte("secret"), key1, aad)

	if _, err := crypto.Decrypt(ciphertext, key2, aad); err == nil {
		t.Fatal("expected error when decrypting with wrong key")
	}
}

func TestDecryptWithWrongAADFails(t *testing.T) {
	key := testKey(t)
	ciphertext, _ := crypto.Encrypt([]byte("secret"), key, []byte("instance_config:smtp_password"))

	if _, err := crypto.Decrypt(ciphertext, key, []byte("instance_config:other_key")); err == nil {
		t.Fatal("decrypt with mismatched AAD must fail (prevents cross-slot swap attack)")
	}
}

func TestEncryptRejectsInvalidKeyLength(t *testing.T) {
	if _, err := crypto.Encrypt([]byte("data"), []byte("short-key"), nil); err == nil {
		t.Fatal("expected error for invalid key length")
	}
}

func TestDecryptRejectsInvalidKeyLength(t *testing.T) {
	if _, err := crypto.Decrypt(make([]byte, 100), []byte("short-key"), nil); err == nil {
		t.Fatal("expected error for invalid key length")
	}
}

// TestDecryptAcceptsLegacyV0 builds a v0 blob (single-layer AES-GCM, no
// version byte, no AAD) directly using the stdlib and asserts Decrypt still
// reads it. This path protects production DB rows written before the envelope
// upgrade (signing_keys.private_key_encrypted, users.totp_secret_encrypted,
// instance_config encrypted SMTP password).
func TestDecryptAcceptsLegacyV0(t *testing.T) {
	key := testKey(t)
	plaintext := []byte("legacy-blob")

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	legacy := aesGCM.Seal(nonce, nonce, plaintext, nil)

	got, err := crypto.Decrypt(legacy, key, []byte("any-aad-ignored-on-v0"))
	if err != nil {
		t.Fatalf("Decrypt rejected legacy v0 blob: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("legacy decrypt round-trip: got %q, want %q", got, plaintext)
	}
}

// TestDecryptAcceptsLegacyV0EvenWhenFirstByteIs01 constructs a v0 blob whose
// nonce[0] happens to be 0x01 and asserts it still decrypts. Guards against
// a naive version-byte dispatch that would mis-route legacy blobs.
func TestDecryptAcceptsLegacyV0EvenWhenFirstByteIs01(t *testing.T) {
	key := testKey(t)
	plaintext := []byte("collision")

	block, _ := aes.NewCipher(key)
	aesGCM, _ := cipher.NewGCM(block)
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	nonce[0] = 0x01
	legacy := aesGCM.Seal(nonce, nonce, plaintext, nil)

	got, err := crypto.Decrypt(legacy, key, nil)
	if err != nil {
		t.Fatalf("v0 blob with nonce[0]=0x01 rejected: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("mismatch: got %q want %q", got, plaintext)
	}
}

// TestSwapDetection proves that swapping a v1 blob into a different storage
// slot (different AAD) fails decryption — the core value prop of AAD binding.
func TestSwapDetection(t *testing.T) {
	key := testKey(t)
	ctA, _ := crypto.Encrypt([]byte("smtp-password-value"), key, []byte("instance_config:smtp_password"))
	ctB, _ := crypto.Encrypt([]byte("totp-secret-value"), key, []byte("user_totp_secret:user-123"))

	// Swap: try to read slot A's ciphertext as if it were slot B.
	if _, err := crypto.Decrypt(ctA, key, []byte("user_totp_secret:user-123")); err == nil {
		t.Fatal("swap A->B must fail: AAD binding broken")
	}
	if _, err := crypto.Decrypt(ctB, key, []byte("instance_config:smtp_password")); err == nil {
		t.Fatal("swap B->A must fail: AAD binding broken")
	}
}
