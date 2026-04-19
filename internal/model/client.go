package model

import (
	"fmt"
	"strings"
)

const clientNameMaxLen = 100

// ValidateClientName trims and validates an OIDC client name. Returns the
// trimmed value. 1..100 chars after trim.
func ValidateClientName(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("client name is required")
	}
	if len(trimmed) > clientNameMaxLen {
		return "", fmt.Errorf("client name must be %d characters or fewer", clientNameMaxLen)
	}
	return trimmed, nil
}
