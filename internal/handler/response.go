package handler

import (
	"encoding/json"
	"net/http"
	"strings"
)

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
	}
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{
		"error":   code,
		"message": message,
	})
}

// isSecureURL returns true iff publicURL starts with "https://". Used by
// handler constructors to derive the Secure flag on Set-Cookie headers so
// cookies are not sent over plaintext connections in production.
func isSecureURL(publicURL string) bool {
	return strings.HasPrefix(publicURL, "https://")
}

// setSessionCookie writes the schlass_session cookie to w. Used by both
// AuthHandler (PostLogin, PostChangePassword) and MfaHandler
// (PostEnrollmentComplete) so the production cookie attributes stay in one
// place: HttpOnly, SameSite=Lax, Path=/, 24h Max-Age, and the Secure flag
// toggled by the public URL scheme.
//
// SameSite=Lax (not Strict) is required because /authorize is an entry
// point for cross-site top-level navigations from relying parties
// (Grafana, oauth2-proxy, …). Strict would block the session cookie on
// that navigation, forcing the user to re-authenticate on every OIDC
// round-trip and leaking a duplicate session. Lax still rejects the
// cookie on cross-site sub-resource requests and on cross-site POSTs,
// which is the CSRF threat model the flag protects against.
func setSessionCookie(w http.ResponseWriter, token string, secure bool) {
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
