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

// Session holds identity (UserID only — email/role/status are fetched fresh
// from PG on every authed request, so edits take effect immediately) plus
// metadata (Created/LastSeen/IP/UA). PendingReturnTo carries a sanitized
// OIDC return_to across force-password-change; cleared after rotation.
type Session struct {
	UserID               string    `json:"user_id"`
	CreatedAt            time.Time `json:"created_at"`
	LastSeenAt           time.Time `json:"last_seen_at"`
	IPAddress            string    `json:"ip_address"`
	UserAgent            string    `json:"user_agent"`
	PendingReturnTo      string    `json:"pending_return_to,omitempty"`
	AuditViewedInSession bool      `json:"audit_viewed_in_session,omitempty"`
	LastMFAAt            time.Time `json:"last_mfa_at,omitempty"`
}

// SessionWithToken carries the opaque token (Valkey key) alongside so
// per-device delete has both metadata and handle.
type SessionWithToken struct {
	Token string `json:"token"`
	Session
}

// Store: Create generates the opaque token server-side (crypto/rand,
// prevents session fixation by construction). Get updates LastSeenAt and
// slides TTL. Delete takes userID so the SREM from user_sessions:<userID>
// happens alongside the session DEL in one pipeline.
type Store interface {
	Create(ctx context.Context, userID, ipAddress, userAgent string) (token string, err error)
	Get(ctx context.Context, token string) (*Session, error)
	Delete(ctx context.Context, userID, token string) error
	ListByUser(ctx context.Context, userID string) ([]*SessionWithToken, error)
	DeleteAllForUser(ctx context.Context, userID string) error

	// CreateWithPendingReturnTo — used by PostLogin force_password_change
	// branch. Caller must have already SanitizeReturnTo'd; store does not
	// re-validate. Empty returnTo equivalent to Create.
	CreateWithPendingReturnTo(ctx context.Context, userID, ipAddress, userAgent, returnTo string) (token string, err error)
	ClearPendingReturnTo(ctx context.Context, token string) error
	MarkAuditViewed(ctx context.Context, token string) error
	MarkMFAVerified(ctx context.Context, token string) error
}

var ErrNotFound = errors.New("session: not found")

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

func userSessionsKey(userID string) string {
	return "user_sessions:" + userID
}

// Create: SET + SADD + EXPIRE as a pipeline (not MULTI/EXEC). If a middle
// command fails, session key may exist without its entry in
// user_sessions:<id>. Still usable for auth (Get doesn't touch the SET),
// just won't appear in ListByUser. Blast radius bounded by session TTL.
func (s *valkeyStore) Create(ctx context.Context, userID, ipAddress, userAgent string) (string, error) {
	return s.CreateWithPendingReturnTo(ctx, userID, ipAddress, userAgent, "")
}

func (s *valkeyStore) CreateWithPendingReturnTo(ctx context.Context, userID, ipAddress, userAgent, returnTo string) (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("session: generate token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(buf[:])

	now := time.Now().UTC()
	sess := Session{
		UserID:          userID,
		CreatedAt:       now,
		LastSeenAt:      now,
		IPAddress:       ipAddress,
		UserAgent:       userAgent,
		PendingReturnTo: returnTo,
	}
	payload, err := json.Marshal(sess)
	if err != nil {
		return "", fmt.Errorf("session: marshal: %w", err)
	}

	pipe := s.client.Pipeline()
	pipe.Set(ctx, sessionKey(token), payload, s.ttl)
	pipe.SAdd(ctx, userSessionsKey(userID), token)
	pipe.Expire(ctx, userSessionsKey(userID), s.ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return "", fmt.Errorf("session: pipeline set/sadd/expire: %w", err)
	}
	return token, nil
}

// Get: TTL slide failure is non-fatal (slog.Warn). Worst case — user's
// entry in ListByUser silently disappears before the session itself
// expires; admin UI degrades but auth still works. Next Get re-extends.
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

	sess.LastSeenAt = time.Now().UTC()
	newPayload, err := json.Marshal(sess)
	if err != nil {
		return nil, fmt.Errorf("session: remarshal: %w", err)
	}
	pipe := s.client.Pipeline()
	pipe.Set(ctx, key, newPayload, s.ttl)
	pipe.Expire(ctx, userSessionsKey(sess.UserID), s.ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		slog.Warn("session: TTL slide failed, session will expire at original deadline",
			"error", err,
			"user_id", sess.UserID)
	}
	return &sess, nil
}

func (s *valkeyStore) Delete(ctx context.Context, userID, token string) error {
	pipe := s.client.Pipeline()
	pipe.Del(ctx, sessionKey(token))
	pipe.SRem(ctx, userSessionsKey(userID), token)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("session: pipeline del/srem: %w", err)
	}
	return nil
}

func (s *valkeyStore) ListByUser(ctx context.Context, userID string) ([]*SessionWithToken, error) {
	tokens, err := s.client.SMembers(ctx, userSessionsKey(userID)).Result()
	if err != nil {
		return nil, fmt.Errorf("session: smembers: %w", err)
	}
	if len(tokens) == 0 {
		return nil, nil
	}

	pipe := s.client.Pipeline()
	cmds := make([]*redis.StringCmd, len(tokens))
	for i, t := range tokens {
		cmds[i] = pipe.Get(ctx, sessionKey(t))
	}
	_, _ = pipe.Exec(ctx) // per-command errors checked below

	sessions := make([]*SessionWithToken, 0, len(tokens))
	for i, cmd := range cmds {
		raw, err := cmd.Bytes()
		if errors.Is(err, redis.Nil) {
			// Stale SET entry — session key expired, token still in SET.
			// Lazily skip; cleaned up on next DeleteAllForUser or SET TTL.
			continue
		}
		if err != nil {
			// Surface rather than return partial — partial would silently
			// break the admin force-terminate flow (session kept alive).
			return nil, fmt.Errorf("session: listbyuser get %s: %w", tokens[i], err)
		}
		var sess Session
		if err := json.Unmarshal(raw, &sess); err != nil {
			return nil, fmt.Errorf("session: listbyuser unmarshal %s: %w", tokens[i], err)
		}
		sessions = append(sessions, &SessionWithToken{Token: tokens[i], Session: sess})
	}
	return sessions, nil
}

// ClearPendingReturnTo uses SET ... KEEPTTL to preserve TTL. Runs at most
// once per login (tail of PostChangePassword) — not a hot path.
func (s *valkeyStore) ClearPendingReturnTo(ctx context.Context, token string) error {
	key := sessionKey(token)
	raw, err := s.client.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("session: clear pending return_to get: %w", err)
	}
	var sess Session
	if err := json.Unmarshal(raw, &sess); err != nil {
		return fmt.Errorf("session: clear pending return_to unmarshal: %w", err)
	}
	if sess.PendingReturnTo == "" {
		return nil
	}
	sess.PendingReturnTo = ""
	payload, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("session: clear pending return_to marshal: %w", err)
	}
	if err := s.client.SetArgs(ctx, key, payload, redis.SetArgs{KeepTTL: true}).Err(); err != nil {
		return fmt.Errorf("session: clear pending return_to set: %w", err)
	}
	return nil
}

func (s *valkeyStore) MarkAuditViewed(ctx context.Context, token string) error {
	key := sessionKey(token)
	raw, err := s.client.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("session: mark audit viewed get: %w", err)
	}
	var sess Session
	if err := json.Unmarshal(raw, &sess); err != nil {
		return fmt.Errorf("session: mark audit viewed unmarshal: %w", err)
	}
	if sess.AuditViewedInSession {
		return nil
	}
	sess.AuditViewedInSession = true
	payload, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("session: mark audit viewed marshal: %w", err)
	}
	if err := s.client.SetArgs(ctx, key, payload, redis.SetArgs{KeepTTL: true}).Err(); err != nil {
		return fmt.Errorf("session: mark audit viewed set: %w", err)
	}
	return nil
}

func (s *valkeyStore) MarkMFAVerified(ctx context.Context, token string) error {
	key := sessionKey(token)
	raw, err := s.client.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("session: mark mfa verified get: %w", err)
	}
	var sess Session
	if err := json.Unmarshal(raw, &sess); err != nil {
		return fmt.Errorf("session: mark mfa verified unmarshal: %w", err)
	}
	sess.LastMFAAt = time.Now().UTC()
	payload, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("session: mark mfa verified marshal: %w", err)
	}
	if err := s.client.SetArgs(ctx, key, payload, redis.SetArgs{KeepTTL: true}).Err(); err != nil {
		return fmt.Errorf("session: mark mfa verified set: %w", err)
	}
	return nil
}

func (s *valkeyStore) DeleteAllForUser(ctx context.Context, userID string) error {
	tokens, err := s.client.SMembers(ctx, userSessionsKey(userID)).Result()
	if err != nil {
		return fmt.Errorf("session: smembers: %w", err)
	}

	pipe := s.client.Pipeline()
	for _, t := range tokens {
		pipe.Del(ctx, sessionKey(t))
	}
	pipe.Del(ctx, userSessionsKey(userID))
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("session: pipeline del-all: %w", err)
	}
	return nil
}
