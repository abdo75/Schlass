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
