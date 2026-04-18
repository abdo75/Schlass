package oidc

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// NewCorrelationID returns a fresh opaque identifier for /oidc/error pages.
// 16 bytes random → 32 hex chars → prefix "err_". Matches spec §5c.
func NewCorrelationID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("correlation id: %w", err)
	}
	return "err_" + hex.EncodeToString(buf[:]), nil
}
