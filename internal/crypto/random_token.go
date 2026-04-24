package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// RandomToken generates an n-byte cryptographically random token encoded as
// base64url (no padding). Used for session, MFA enrollment/challenge, and
// password-reset tokens.
func RandomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
