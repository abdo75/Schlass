// Package revokebefore stores and reads per-user revocation cutoff timestamps.
// Access tokens and refresh tokens issued before revoke_before are rejected
// at /token refresh and /userinfo.
//
// Key shape: user:revoke_before:<user_id>
// Value:     unix seconds as a decimal string
// TTL:       30 days (generous upper bound; refresh tokens max out at 24h)
package revokebefore

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	keyPrefix = "user:revoke_before:"
	ttl       = 30 * 24 * time.Hour
)

// ErrNotSet is returned by Get when no revoke_before cutoff has been written
// for the given user. Callers should treat this as "allow all tokens" — the
// absence of a cutoff is the normal case for unmodified accounts.
var ErrNotSet = errors.New("revoke_before: not set")

func key(userID string) string {
	return keyPrefix + userID
}

// Set writes the cutoff timestamp for userID. The value is stored as unix
// seconds; sub-second precision is truncated. TTL is always reset to 30 days
// on each call so back-to-back mutations don't let the key expire prematurely.
//
// Called post-commit by mutation handlers (disable, reset-password, reset-mfa,
// self-change-password, self-disable-mfa). Caller logs errors; this function
// returns them verbatim.
func Set(ctx context.Context, v redis.Cmdable, userID string, at time.Time) error {
	secs := at.Unix()
	return v.Set(ctx, key(userID), strconv.FormatInt(secs, 10), ttl).Err()
}

// SetNow writes the cutoff for userID to the next whole second after now.
// Readers compare with strict "<" (spec §5g), so rounding up is what makes
// "mutation + still-outstanding token issued in the same wall-clock second"
// resolve as stale. Without this bump, second-granularity truncation would let
// an outstanding token issued a few hundred ms before the mutation survive.
// Conversely a fresh login after the mutation produces iat ≥ cutoff in the
// next full second and is accepted. Used by all mutation handlers.
func SetNow(ctx context.Context, v redis.Cmdable, userID string) error {
	cutoff := time.Now().UTC().Truncate(time.Second).Add(time.Second)
	return Set(ctx, v, userID, cutoff)
}

// Get returns the revocation cutoff for userID.
//
// Returns (time.Time{}, ErrNotSet, nil) when no cutoff has been written —
// callers should allow the token in that case.
//
// Other errors (transport, parse) return (time.Time{}, err) where err wraps
// the underlying cause; callers should log at Warn level and allow the token
// to avoid availability hazards on transient Valkey failures.
func Get(ctx context.Context, v redis.Cmdable, userID string) (time.Time, error) {
	val, err := v.Get(ctx, key(userID)).Result()
	if errors.Is(err, redis.Nil) {
		return time.Time{}, ErrNotSet
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("revoke_before: get %s: %w", userID, err)
	}
	secs, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("revoke_before: parse value %q for %s: %w", val, userID, err)
	}
	return time.Unix(secs, 0).UTC(), nil
}
