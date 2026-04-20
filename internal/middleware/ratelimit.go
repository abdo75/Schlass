package middleware

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

type RateLimiter struct {
	client *redis.Client
	prefix string
	limit  int64
	window time.Duration
	// FailClosed toggles behavior on Valkey error. false (default)
	// passes the request through, preserving availability under a
	// Valkey blip. true responds 503 — appropriate for security-
	// critical routes (login, MFA challenge, password-reset) where
	// an outage must not remove the brute-force guard.
	FailClosed bool
}

func NewRateLimiter(client *redis.Client, prefix string, limit int64, window time.Duration) *RateLimiter {
	return &RateLimiter{
		client: client,
		prefix: prefix,
		limit:  limit,
		window: window,
	}
}

func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		key := fmt.Sprintf("%s:%s", rl.prefix, ip)

		allowed, retryAfter, err := rl.allow(r.Context(), key)
		if err != nil {
			slog.Error("rate limiter error", "error", err, "key", key, "fail_closed", rl.FailClosed) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
			if rl.FailClosed {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"error":"SERVICE_UNAVAILABLE","message":"Service temporarily unavailable. Please try again."}`))
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		if !allowed {
			w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"RATE_LIMITED","message":"Too many requests. Try again later."}`))
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (rl *RateLimiter) allow(ctx context.Context, key string) (bool, time.Duration, error) {
	now := time.Now()
	nowMicro := now.UnixMicro()
	windowStartMicro := nowMicro - rl.window.Microseconds()
	member := fmt.Sprintf("%d-%d", nowMicro, rand.Int64()) //nolint:gosec // math/rand is intentional: member is only used as a unique Redis set key suffix, not for security

	pipe := rl.client.Pipeline()
	pipe.ZRemRangeByScore(ctx, key, "-inf", strconv.FormatInt(windowStartMicro, 10))
	pipe.ZAdd(ctx, key, redis.Z{Score: float64(nowMicro), Member: member})
	cardCmd := pipe.ZCard(ctx, key)
	pipe.Expire(ctx, key, rl.window*2)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return false, 0, err
	}

	count := cardCmd.Val()
	if count > rl.limit {
		rl.client.ZRem(ctx, key, member)
		return false, rl.window, nil
	}

	return true, 0, nil
}

func clientIP(r *http.Request) string {
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
