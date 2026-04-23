package auth

import (
	"net"
	"net/http"
)

// extractClientIP returns the leftmost IP from X-Forwarded-For when present,
// falling back to RemoteAddr. Shared by handlers that log client IPs for audit.
func extractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
