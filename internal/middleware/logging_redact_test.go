package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func runWithLogs(t *testing.T, h http.Handler, req *http.Request) string {
	t.Helper()
	var buf bytes.Buffer
	orig := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(orig) })
	RequestLogging(h).ServeHTTP(httptest.NewRecorder(), req)
	return buf.String()
}

func TestRequestLogging_RedactsResetPasswordToken(t *testing.T) {
	noop := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/reset-password/A-TOKEN-THAT-SHOULD-NOT-LEAK", nil)
	got := runWithLogs(t, noop, req)
	if strings.Contains(got, "A-TOKEN-THAT-SHOULD-NOT-LEAK") {
		t.Fatalf("token leaked to logs: %s", got)
	}
	var line map[string]any
	_ = json.Unmarshal([]byte(strings.TrimSpace(strings.Split(got, "\n")[0])), &line)
	if p, _ := line["path"].(string); p != "/reset-password/[redacted]" {
		t.Fatalf("path = %q, want /reset-password/[redacted]", p)
	}
}

func TestRequestLogging_PreservesNonSensitivePaths(t *testing.T) {
	noop := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/users?limit=10", nil)
	got := runWithLogs(t, noop, req)
	if !strings.Contains(got, "/api/users") {
		t.Fatalf("non-sensitive path should be preserved: %s", got)
	}
}
