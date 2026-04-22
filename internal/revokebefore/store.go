// Package revokebefore stores per-user revocation cutoff timestamps.
// Tokens with iat < revoke_before are rejected at /token refresh and
// /userinfo.
//
// Key:   user:revoke_before:<user_id>
// Value: unix seconds (decimal string)
// TTL:   30 days
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

// ErrNotSet — no cutoff written. Callers treat as "allow all tokens".
var ErrNotSet = errors.New("revoke_before: not set")

func key(userID string) string {
	return keyPrefix + userID
}

// Set: stores unix seconds, always resets 30d TTL so back-to-back mutations
// don't let the key expire prematurely.
func Set(ctx context.Context, v redis.Cmdable, userID string, at time.Time) error {
	secs := at.Unix()
	return v.Set(ctx, key(userID), strconv.FormatInt(secs, 10), ttl).Err()
}

// SetNow rounds cutoff UP to the next whole second. Readers use strict "<"
// (spec §5g); without the round-up, second-granularity truncation would let
// a token issued a few hundred ms before the mutation survive. Fresh logins
// land in the next full second with iat ≥ cutoff and are accepted.
func SetNow(ctx context.Context, v redis.Cmdable, userID string) error {
	cutoff := time.Now().UTC().Truncate(time.Second).Add(time.Second)
	return Set(ctx, v, userID, cutoff)
}

// Get returns (zero, ErrNotSet) when no cutoff is written. Transport/parse
// errors return a wrapped err; callers log at Warn and allow the token to
// avoid availability hazards on transient Valkey failures.
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
