package handler

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// generateRandomToken returns a base64url-encoded random string of n bytes.
// Used for enrollment and challenge tokens — short-lived session-analogue
// values that live only in Valkey.
func generateRandomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
