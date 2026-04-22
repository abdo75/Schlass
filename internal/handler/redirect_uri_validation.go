package handler

import (
	"fmt"
	"net/url"
	"strings"
)

const redirectURIMaxLen = 2048

// loopbackHosts per RFC 8252 §7.3.
var loopbackHosts = map[string]struct{}{
	"localhost": {},
	"127.0.0.1": {},
	"[::1]":     {},
	"::1":       {},
}

// ValidateRedirectURIInput enforces scheme + no-fragment + no-wildcard +
// length + loopback-exception rules. All rules fail closed: len ≤ 2048,
// url.Parse succeeds, no whitespace, no fragment, no wildcard chars, and
// scheme = https OR scheme = http AND host ∈ loopback set.
func ValidateRedirectURIInput(raw string) error {
	if raw == "" {
		return fmt.Errorf("redirect uri cannot be empty")
	}
	if len(raw) > redirectURIMaxLen {
		return fmt.Errorf("redirect uri exceeds %d characters", redirectURIMaxLen)
	}
	if strings.ContainsAny(raw, " \t\r\n") {
		return fmt.Errorf("redirect uri contains whitespace")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("redirect uri parse: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("redirect uri must include scheme and host")
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return fmt.Errorf("redirect uri must not contain a fragment")
	}
	if strings.Contains(u.Host, "*") || strings.Contains(u.Path, "*") {
		return fmt.Errorf("redirect uri must not contain wildcards")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if _, ok := loopbackHosts[host]; ok {
			return nil
		}
		return fmt.Errorf("http redirect uri allowed only for loopback host (got %q)", host)
	default:
		return fmt.Errorf("redirect uri scheme must be https or http+loopback (got %q)", u.Scheme)
	}
}
