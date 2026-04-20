package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/abdo75/Schlass/internal/middleware"
)

func TestSecurityHeadersAreSet(t *testing.T) {
	handler := middleware.SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequestWithContext(t.Context(), "GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	expected := map[string]string{
		"Strict-Transport-Security": "max-age=63072000; includeSubDomains",
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"Permissions-Policy":        "camera=(), microphone=(), geolocation=()",
	}

	for header, want := range expected {
		got := rec.Header().Get(header)
		if got != want {
			t.Errorf("header %s = %q, want %q", header, got, want)
		}
	}

	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("Content-Security-Policy header is missing")
	}
}

func TestSecurityHeaders_ScopesNoReferrerToResetRoutes(t *testing.T) {
	cases := map[string]string{
		"/reset-password/abc":           "no-referrer",
		"/forgot-password":              "no-referrer",
		"/api/password-reset/validate":  "no-referrer",
		"/api/password-reset/request":   "no-referrer",
		"/api/password-reset/confirm":   "no-referrer",
		"/api/users":                    "strict-origin-when-cross-origin",
		"/":                             "strict-origin-when-cross-origin",
	}
	h := middleware.SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	for path, want := range cases {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if got := rec.Header().Get("Referrer-Policy"); got != want {
				t.Fatalf("Referrer-Policy for %s = %q, want %q", path, got, want)
			}
		})
	}
}
