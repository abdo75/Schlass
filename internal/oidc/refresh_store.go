package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	refreshKeyPrefix       = "oidc:refresh:"
	refreshFamilyKeyPrefix = "oidc:refresh:family:"
)

var (
	ErrRefreshUnknownOrExpired = errors.New("refresh: unknown or expired")
	ErrRefreshReuseDetected    = errors.New("refresh: already used (reuse detected)")
)

// RefreshPayload is the body stored per refresh token in Valkey.
type RefreshPayload struct {
	UserID    string   `json:"user_id"`
	ClientID  string   `json:"client_id"`
	Scopes    []string `json:"scopes"`
	FamilyID  string   `json:"family_id"`
	CreatedAt int64    `json:"created_at"`
	Expires   int64    `json:"exp"`
	Used      bool     `json:"used"`
}

// RefreshStore is the refresh-token persistence contract.
//
// Tokens are opaque 32-byte random strings stored hashed in Valkey. Each token
// belongs to a family (family_id) that spans every rotation in a chain. Reuse
// of an already-rotated token triggers RevokeFamily per OAuth 2.1 §4.13.
type RefreshStore interface {
	// Create stores a new refresh under oidc:refresh:<sha256(token)>. The raw
	// token is generated internally (32 bytes from crypto/rand, base64url). The
	// token is SADD'd to the oidc:refresh:family:<family_id> SET.
	// Returns the raw token (to be returned in the /token response once).
	Create(ctx context.Context, payload RefreshPayload) (rawToken string, err error)

	// Consume looks up a refresh by its sha256 hash, returning the payload if
	// present and used=false, or (nil, ErrRefreshUnknownOrExpired) /
	// (payload, ErrRefreshReuseDetected) otherwise. MarkUsed must be called
	// inside the same logical operation as the response to avoid issuing
	// duplicate new refreshes from one presented refresh.
	Consume(ctx context.Context, rawToken string) (*RefreshPayload, error)

	// MarkUsed flips used=true on the keyed refresh. Idempotent.
	MarkUsed(ctx context.Context, rawToken string) error

	// RevokeFamily atomically deletes every refresh under the family and the
	// family SET. Called on reuse detection per OAuth 2.1 §4.13.
	RevokeFamily(ctx context.Context, familyID string) error

	// Get is a non-mutating lookup used by tests/diagnostics.
	Get(ctx context.Context, rawToken string) (*RefreshPayload, error)
}

type valkeyRefreshStore struct {
	client *redis.Client
}

// NewRefreshStore constructs the production Valkey-backed RefreshStore.
func NewRefreshStore(client *redis.Client) RefreshStore {
	return &valkeyRefreshStore{client: client}
}

func (s *valkeyRefreshStore) Create(ctx context.Context, payload RefreshPayload) (string, error) {
	now := time.Now().Unix()
	ttlSecs := payload.Expires - now
	if ttlSecs <= 0 {
		return "", fmt.Errorf("refresh create: token already expired")
	}

	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("refresh create: entropy: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(buf[:])
	hash := sha256hexStr(token)

	payload.Used = false
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("refresh create: marshal: %w", err)
	}

	ttl := time.Duration(ttlSecs) * time.Second
	pipe := s.client.Pipeline()
	pipe.Set(ctx, refreshKeyPrefix+hash, body, ttl)
	pipe.SAdd(ctx, refreshFamilyKeyPrefix+payload.FamilyID, hash)
	pipe.Expire(ctx, refreshFamilyKeyPrefix+payload.FamilyID, ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return "", fmt.Errorf("refresh create: pipeline: %w", err)
	}
	return token, nil
}

func (s *valkeyRefreshStore) Consume(ctx context.Context, rawToken string) (*RefreshPayload, error) {
	hash := sha256hexStr(rawToken)
	body, err := s.client.Get(ctx, refreshKeyPrefix+hash).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrRefreshUnknownOrExpired
	}
	if err != nil {
		return nil, fmt.Errorf("refresh consume: get: %w", err)
	}
	var p RefreshPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("refresh consume: unmarshal: %w", err)
	}
	if p.Used {
		return &p, ErrRefreshReuseDetected
	}
	return &p, nil
}

func (s *valkeyRefreshStore) MarkUsed(ctx context.Context, rawToken string) error {
	hash := sha256hexStr(rawToken)
	key := refreshKeyPrefix + hash

	ttl, err := s.client.TTL(ctx, key).Result()
	if errors.Is(err, redis.Nil) || ttl <= 0 {
		return nil // already expired or missing — idempotent
	}
	if err != nil {
		return fmt.Errorf("refresh mark used: ttl: %w", err)
	}

	body, err := s.client.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil // expired between TTL and GET — idempotent
	}
	if err != nil {
		return fmt.Errorf("refresh mark used: get: %w", err)
	}

	var p RefreshPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return fmt.Errorf("refresh mark used: unmarshal: %w", err)
	}
	if p.Used {
		return nil // already marked — idempotent
	}
	p.Used = true
	newBody, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("refresh mark used: marshal: %w", err)
	}
	if err := s.client.Set(ctx, key, newBody, ttl).Err(); err != nil {
		return fmt.Errorf("refresh mark used: set: %w", err)
	}
	return nil
}

func (s *valkeyRefreshStore) RevokeFamily(ctx context.Context, familyID string) error {
	setKey := refreshFamilyKeyPrefix + familyID
	hashes, err := s.client.SMembers(ctx, setKey).Result()
	if err != nil {
		return fmt.Errorf("refresh revoke family: smembers: %w", err)
	}
	// Idempotent: empty family (already revoked or never created) is fine.
	pipe := s.client.Pipeline()
	for _, h := range hashes {
		pipe.Del(ctx, refreshKeyPrefix+h)
	}
	pipe.Del(ctx, setKey)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("refresh revoke family: pipeline: %w", err)
	}
	return nil
}

func (s *valkeyRefreshStore) Get(ctx context.Context, rawToken string) (*RefreshPayload, error) {
	hash := sha256hexStr(rawToken)
	body, err := s.client.Get(ctx, refreshKeyPrefix+hash).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrRefreshUnknownOrExpired
	}
	if err != nil {
		return nil, fmt.Errorf("refresh get: %w", err)
	}
	var p RefreshPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("refresh get: unmarshal: %w", err)
	}
	return &p, nil
}

// sha256hexStr returns the lowercase hex-encoded SHA-256 of s.
// Consistent with auth-code hashing in the codebase.
func sha256hexStr(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
