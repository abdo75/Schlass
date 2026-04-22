// Per-client revoke_before — analog of the per-user cutoff in store.go.
// Written post-commit by DELETE /api/clients/:id; read by bearer_auth and
// the /token refresh grant. Same second-granularity "round up" as the user
// variant so a token issued in the same wall-clock second as the mutation
// resolves as stale.
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

func ClientSet(ctx context.Context, v redis.Cmdable, clientID string, at time.Time) error {
	return v.Set(ctx, clientKey(clientID), strconv.FormatInt(at.Unix(), 10), ttl).Err()
}

func ClientSetNow(ctx context.Context, v redis.Cmdable, clientID string) error {
	cutoff := time.Now().UTC().Truncate(time.Second).Add(time.Second)
	return ClientSet(ctx, v, clientID, cutoff)
}

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
