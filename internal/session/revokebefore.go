// Per-user and per-client revoke_before cutoff timestamps.
// Tokens with iat < revoke_before are rejected at /token refresh and
// /userinfo. Same second-granularity "round up" closes the same-second
// race: a token issued a few hundred ms before the mutation survives
// otherwise; fresh logins land in the next full second with iat ≥ cutoff.
//
// User key:   user:revoke_before:<user_id>
// Client key: client:revoke_before:<client_id>
// Value:      unix seconds (decimal string)
// TTL:        30 days
package session

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	revokeBeforeKeyPrefix       = "user:revoke_before:"
	revokeBeforeClientKeyPrefix = "client:revoke_before:"
	revokeBeforeTTL             = 30 * 24 * time.Hour
)

// ErrRevokeBeforeNotSet — no cutoff written. Callers treat as "allow all tokens".
var ErrRevokeBeforeNotSet = errors.New("revoke_before: not set")

func revokeBeforeKey(userID string) string {
	return revokeBeforeKeyPrefix + userID
}

func revokeBeforeClientKey(clientID string) string {
	return revokeBeforeClientKeyPrefix + clientID
}

// RevokeBeforeSet stores unix seconds, always resets 30d TTL so back-to-back
// mutations don't let the key expire prematurely.
func RevokeBeforeSet(ctx context.Context, v redis.Cmdable, userID string, at time.Time) error {
	secs := at.Unix()
	return v.Set(ctx, revokeBeforeKey(userID), strconv.FormatInt(secs, 10), revokeBeforeTTL).Err()
}

// RevokeBeforeSetNow rounds cutoff UP to the next whole second. Readers use
// strict "<" (spec §5g); without the round-up, second-granularity truncation
// would let a token issued a few hundred ms before the mutation survive.
// Fresh logins land in the next full second with iat ≥ cutoff and are accepted.
func RevokeBeforeSetNow(ctx context.Context, v redis.Cmdable, userID string) error {
	cutoff := time.Now().UTC().Truncate(time.Second).Add(time.Second)
	return RevokeBeforeSet(ctx, v, userID, cutoff)
}

// RevokeBeforeGet returns (zero, ErrRevokeBeforeNotSet) when no cutoff is
// written. Transport/parse errors return a wrapped err; callers log at Warn
// and allow the token to avoid availability hazards on transient Valkey failures.
func RevokeBeforeGet(ctx context.Context, v redis.Cmdable, userID string) (time.Time, error) {
	val, err := v.Get(ctx, revokeBeforeKey(userID)).Result()
	if errors.Is(err, redis.Nil) {
		return time.Time{}, ErrRevokeBeforeNotSet
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

// RevokeBeforeClientSet: per-client variant written post-commit by
// DELETE /api/clients/:id; read by bearer_auth and the /token refresh grant.
func RevokeBeforeClientSet(ctx context.Context, v redis.Cmdable, clientID string, at time.Time) error {
	return v.Set(ctx, revokeBeforeClientKey(clientID), strconv.FormatInt(at.Unix(), 10), revokeBeforeTTL).Err()
}

// RevokeBeforeClientSetNow rounds up to the next whole second — same as
// RevokeBeforeSetNow so a token issued in the same wall-clock second as the
// mutation resolves as stale.
func RevokeBeforeClientSetNow(ctx context.Context, v redis.Cmdable, clientID string) error {
	cutoff := time.Now().UTC().Truncate(time.Second).Add(time.Second)
	return RevokeBeforeClientSet(ctx, v, clientID, cutoff)
}

// RevokeBeforeClientGet returns (zero, ErrRevokeBeforeNotSet) when no cutoff
// is stored. Callers treat the not-set case as "allow all tokens".
func RevokeBeforeClientGet(ctx context.Context, v redis.Cmdable, clientID string) (time.Time, error) {
	val, err := v.Get(ctx, revokeBeforeClientKey(clientID)).Result()
	if errors.Is(err, redis.Nil) {
		return time.Time{}, ErrRevokeBeforeNotSet
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("revoke_before client: get %s: %w", clientID, err)
	}
	secs, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("revoke_before client: parse %q: %w", val, err)
	}
	return time.Unix(secs, 0).UTC(), nil
}
