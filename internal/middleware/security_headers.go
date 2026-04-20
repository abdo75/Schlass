package middleware

import (
	"net/http"
	"strings"
)

// resetPaths is the allowlist of paths that must set the stricter
// Referrer-Policy: no-referrer. Reset tokens travel in the URL path
// on GET /reset-password/:token (SPA route) and in POST bodies on the
// /api/password-reset/* endpoints; in both cases a Referer leak would
// expose the token. The SPA /forgot-password is included for
// consistency (POST-over-fetch today, but a staged phishing page
// linking from the form would still leak the referer).
var resetPaths = []string{
	"/reset-password/",
	"/forgot-password",
	"/api/password-reset/",
}

func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		if isResetPath(r.URL.Path) {
			w.Header().Set("Referrer-Policy", "no-referrer")
		} else {
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		}
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

		next.ServeHTTP(w, r)
	})
}

func isResetPath(path string) bool {
	for _, p := range resetPaths {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}
