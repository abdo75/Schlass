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

func isSecureURL(publicURL string) bool {
	return strings.HasPrefix(publicURL, "https://")
}

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
