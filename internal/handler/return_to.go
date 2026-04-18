package handler

import "net/url"

// SanitizeReturnTo validates a user-supplied return_to and returns its
// canonical relative form (path + optional query). Fails closed.
//
// Rules:
//   - Must parse as a URL.
//   - Scheme either empty (relative) or equal to publicURL's scheme.
//   - Host either empty (relative) or equal to publicURL's host.
//   - Path must be exactly "/authorize".
//
// Rejects protocol-relative, off-origin targets, and trailing-path tricks.
func SanitizeReturnTo(raw, publicURL string) (string, bool) {
	if raw == "" {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	pub, err := url.Parse(publicURL)
	if err != nil {
		return "", false
	}
	if u.Scheme != "" && u.Scheme != pub.Scheme {
		return "", false
	}
	if u.Host != "" && u.Host != pub.Host {
		return "", false
	}
	if u.Path != "/authorize" {
		return "", false
	}
	out := u.Path
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return out, true
}
