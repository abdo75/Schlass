package clients

import (
	"fmt"
	"strings"
)

const clientNameMaxLen = 100

// ValidateClientName returns the trimmed value. 1..100 chars after trim.
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

var KnownScopes = map[string]struct{}{
	"openid":         {},
	"profile":        {},
	"email":          {},
	"offline_access": {},
}

var KnownGrantTypes = map[string]struct{}{
	"authorization_code": {},
	"refresh_token":      {},
}

// ValidateScopes: in ⊆ KnownScopes, no dupes, no empty strings. Empty input
// accepted; caller enforces non-empty if required.
func ValidateScopes(in []string) error {
	seen := map[string]struct{}{}
	for _, s := range in {
		if s == "" {
			return fmt.Errorf("scope entry cannot be empty")
		}
		if _, ok := KnownScopes[s]; !ok {
			return fmt.Errorf("unknown scope %q", s)
		}
		if _, dup := seen[s]; dup {
			return fmt.Errorf("duplicate scope %q", s)
		}
		seen[s] = struct{}{}
	}
	return nil
}

// ValidateGrantTypes: in ⊆ KnownGrantTypes, non-empty, no dupes.
func ValidateGrantTypes(in []string) error {
	if len(in) == 0 {
		return fmt.Errorf("at least one grant type is required")
	}
	seen := map[string]struct{}{}
	for _, g := range in {
		if _, ok := KnownGrantTypes[g]; !ok {
			return fmt.Errorf("unknown grant type %q", g)
		}
		if _, dup := seen[g]; dup {
			return fmt.Errorf("duplicate grant type %q", g)
		}
		seen[g] = struct{}{}
	}
	return nil
}
