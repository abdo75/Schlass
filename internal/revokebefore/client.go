// Per-client revoke_before — analog of the per-user cutoff in store.go.
// Written by DELETE /api/clients/:id post-commit. Read by:
//   - bearer_auth middleware (rejects outstanding AT)
//   - /token refresh grant (rejects outstanding refresh)
//
// Uses the same second-granularity "round up" scheme as the user variant so
// a token issued in the same wall-clock second as the mutation resolves as
// stale.
package revokebefore

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

const clientKeyPrefix = "client:revoke_before:"

func clientKey(clientID string) string { return clientKeyPrefix + clientID }

// ClientSet writes the cutoff for clientID. TTL is reset to 30 days.
func ClientSet(ctx context.Context, v redis.Cmdable, clientID string, at time.Time) error {
	return v.Set(ctx, clientKey(clientID), strconv.FormatInt(at.Unix(), 10), ttl).Err()
}

// ClientSetNow bumps the cutoff to the next whole second — mirror of SetNow.
func ClientSetNow(ctx context.Context, v redis.Cmdable, clientID string) error {
	cutoff := time.Now().UTC().Truncate(time.Second).Add(time.Second)
	return ClientSet(ctx, v, clientID, cutoff)
}

// ClientGet returns the cutoff or (zero, ErrNotSet) when absent.
func ClientGet(ctx context.Context, v redis.Cmdable, clientID string) (time.Time, error) {
	val, err := v.Get(ctx, clientKey(clientID)).Result()
	if errors.Is(err, redis.Nil) {
		return time.Time{}, ErrNotSet
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
