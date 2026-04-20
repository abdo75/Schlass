package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// brokenValkey returns a client pointed at an unroutable port.
func brokenValkey() *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:        "127.0.0.1:1",
		MaxRetries:  -1,
		DialTimeout: 100 * time.Millisecond,
	})
}

func TestRateLimiter_FailOpen_ServesRequestOnValkeyError(t *testing.T) {
	rl := NewRateLimiter(brokenValkey(), "test:fo", 5, time.Minute)
	var called bool
	h := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", nil))
	if !called {
		t.Fatal("fail-open limiter should have served the request")
	}
}

func TestRateLimiter_FailClosed_ReturnsServiceUnavailable(t *testing.T) {
	rl := NewRateLimiter(brokenValkey(), "test:fc", 5, time.Minute)
	rl.FailClosed = true
	var called bool
	h := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", nil))
	if called {
		t.Fatal("fail-closed limiter must NOT serve the request on Valkey error")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("code = %d, want 503", rec.Code)
	}
}
