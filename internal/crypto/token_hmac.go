package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const tokenPepperInfo = "password_reset_token_hmac_pepper"

// DeriveTokenPepper is deterministic: same KEK always yields the same pepper,
// so startup re-derivation works without persistence. 32-byte output.
func DeriveTokenPepper(kek []byte) ([]byte, error) {
	if len(kek) != 32 {
		return nil, fmt.Errorf("token pepper: kek must be 32 bytes, got %d", len(kek))
	}
	r := hkdf.New(sha256.New, kek, nil, []byte(tokenPepperInfo))
	pepper := make([]byte, 32)
	if _, err := io.ReadFull(r, pepper); err != nil {
		return nil, fmt.Errorf("token pepper: hkdf read: %w", err)
	}
	return pepper, nil
}

// HMACToken returns HMAC-SHA256(pepper, plaintext). Used for
// password_reset_tokens.token_hash — peppered so a DB dump cannot be
// offline-brute-forced without the KEK.
func HMACToken(plaintext string, pepper []byte) []byte {
	m := hmac.New(sha256.New, pepper)
	m.Write([]byte(plaintext))
	return m.Sum(nil)
}
