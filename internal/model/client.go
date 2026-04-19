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

// KnownScopes is the server-known set of OIDC scopes.
var KnownScopes = map[string]struct{}{
	"openid":         {},
	"profile":        {},
	"email":          {},
	"offline_access": {},
}

// KnownGrantTypes is the server-supported OAuth 2.1 grant type set.
var KnownGrantTypes = map[string]struct{}{
	"authorization_code": {},
	"refresh_token":      {},
}

// ValidateScopes enforces in ⊆ KnownScopes, no duplicates, no empty strings.
// Empty input is accepted; use caller-side policy to reject empty if required.
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

// ValidateGrantTypes enforces in ⊆ KnownGrantTypes, non-empty, no duplicates.
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
