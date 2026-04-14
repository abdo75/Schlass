package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

// Session is the minimal state associated with an authenticated web session.
// Intentionally denormalized to only the user_id; email/role/status are fetched
// fresh from Postgres on every request via the auth middleware. This makes user
// edits (disable, role change, email rename) take effect immediately without
// session-invalidation bookkeeping.
type Session struct {
	UserID string `json:"user_id"`
}

// Store is the session persistence contract.
type Store interface {
	// Create generates a fresh, server-side opaque token, stores the session
	// in Valkey with the configured TTL, and returns the token. The returned
	// token is never read from any client input — this prevents session
	// fixation by construction.
	Create(ctx context.Context, userID string) (token string, err error)

	// Get fetches the session and slides its TTL back to the full configured value.
	// Returns (nil, ErrNotFound) for a genuine miss (handler should treat as 401).
	// Returns (nil, non-nil err) for transport errors (handler should treat as 503).
	Get(ctx context.Context, token string) (*Session, error)

	// Delete removes the session. Idempotent — deleting a non-existent key is not an error.
	Delete(ctx context.Context, token string) error
}

// ErrNotFound is returned by Get when the session token does not exist in Valkey.
var ErrNotFound = errors.New("session: not found")

// NewValkeyStore constructs the production implementation.
// ttl is the absolute TTL and is reset to its full value on every successful Get.
func NewValkeyStore(client *redis.Client, ttl time.Duration) Store {
	return &valkeyStore{client: client, ttl: ttl}
}

type valkeyStore struct {
	client *redis.Client
	ttl    time.Duration
}

func sessionKey(token string) string {
	return "session:" + token
}

func (s *valkeyStore) Create(ctx context.Context, userID string) (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("session: generate token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(buf[:])

	payload, err := json.Marshal(Session{UserID: userID})
	if err != nil {
		return "", fmt.Errorf("session: marshal: %w", err)
	}

	if err := s.client.Set(ctx, sessionKey(token), payload, s.ttl).Err(); err != nil {
		return "", fmt.Errorf("session: set: %w", err)
	}
	return token, nil
}

func (s *valkeyStore) Get(ctx context.Context, token string) (*Session, error) {
	key := sessionKey(token)
	raw, err := s.client.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("session: get: %w", err)
	}

	var sess Session
	if err := json.Unmarshal(raw, &sess); err != nil {
		return nil, fmt.Errorf("session: unmarshal: %w", err)
	}

	// Slide the TTL. If EXPIRE fails we still return the session — the Get
	// has already succeeded and a failed slide is non-fatal.
	if err := s.client.Expire(ctx, key, s.ttl).Err(); err != nil {
		slog.Warn("session: TTL slide failed, session will expire at original deadline", "error", err)
	}
	return &sess, nil
}

func (s *valkeyStore) Delete(ctx context.Context, token string) error {
	// Del on a missing key returns 0, not an error — already idempotent.
	if err := s.client.Del(ctx, sessionKey(token)).Err(); err != nil {
		return fmt.Errorf("session: delete: %w", err)
	}
	return nil
}
