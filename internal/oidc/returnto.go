package oidc

import "net/url"

// SanitizeReturnTo validates a user-supplied return_to and returns its
// canonical relative form (path + optional query). Fails closed: scheme
// + host must match publicURL (or be empty) and path must equal
// "/authorize". Rejects protocol-relative, off-origin, and trailing-path
// tricks — open-redirect guard for the return_to carrier.
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
