package middleware

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func RequestLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := uuid.New().String()

		ctx := WithCorrelationID(r.Context(), id)
		r = r.WithContext(ctx)

		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(rw, r)

		slog.Info("request", //nolint:gosec // G706: slog structured logging is not susceptible to log injection
			"correlation_id", id,
			"method", r.Method,
			"path", redactLogPath(r.URL.Path),
			"status", rw.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"ip", r.RemoteAddr,
		)
	})
}

// redactLogPath replaces token-bearing segments with "[redacted]" so
// aggregated logs cannot be used to mint a working reset link. The SPA
// /reset-password/:token is the only URL carrying a plaintext token in the
// path today.
func redactLogPath(path string) string {
	const prefix = "/reset-password/"
	if strings.HasPrefix(path, prefix) {
		return prefix + "[redacted]"
	}
	return path
}
