package session

import (
	"net/http"
	"strings"
)

// IsSecureURL reports whether publicURL begins with "https://".
func IsSecureURL(publicURL string) bool {
	return strings.HasPrefix(publicURL, "https://")
}

// SetCookie writes the schlass_session cookie.
// SameSite=Lax (not Strict) is required because /authorize is an entry
// point for cross-site top-level navigations from relying parties
// (Grafana, oauth2-proxy, …). Strict would block the session cookie on
// that navigation, forcing the user to re-authenticate on every OIDC
// round-trip and leaking a duplicate session. Lax still rejects the
// cookie on cross-site sub-resource requests and on cross-site POSTs,
// which is the CSRF threat model the flag protects against.
func SetCookie(w http.ResponseWriter, token string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     "schlass_session",
		Value:    token,
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}
