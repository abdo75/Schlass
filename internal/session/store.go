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

// Session is the state associated with an authenticated web session. Split
// conceptually into two kinds of fields:
//
//   - Session identity — UserID only. Email/role/status are fetched fresh
//     from Postgres on every authed request (Sprint 2 decision). This makes
//     user edits (disable, role change, email change) take effect
//     immediately without any session-invalidation bookkeeping.
//
//   - Session metadata — CreatedAt / LastSeenAt / IPAddress / UserAgent.
//     These describe the session itself, not the user. Used by the admin
//     UI's "active sessions" view and by the per-device force-terminate
//     flow added in Sprint 3.
type Session struct {
	UserID     string    `json:"user_id"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	IPAddress  string    `json:"ip_address"`
	UserAgent  string    `json:"user_agent"`
}

// SessionWithToken pairs a Session with its opaque token (the Valkey key).
// Returned by ListByUser so callers have both the metadata and the handle
// needed for per-device delete. The token is the Valkey key, not a field
// in the stored Session value, so it must be carried alongside.
type SessionWithToken struct {
	Token string `json:"token"`
	Session
}

// Store is the session persistence contract.
type Store interface {
	// Create generates a fresh server-side opaque token, writes the session
	// into Valkey with the configured TTL, and SADDs the token to the
	// user_sessions:<user_id> SET for ListByUser / DeleteAllForUser support.
	//
	// The token is never read from client input — the store generates it
	// internally via crypto/rand, preventing session fixation by construction.
	Create(ctx context.Context, userID, ipAddress, userAgent string) (token string, err error)

	// Get fetches the session, updates LastSeenAt, and slides the TTL on
	// the underlying Valkey key via SET value EX ttl (replacing Sprint 2's
	// GET + EXPIRE pair — same roundtrip count, more information written).
	//
	// Returns (nil, ErrNotFound) on genuine miss (handlers treat as 401).
	// Returns (nil, non-nil err) on transport errors (handlers treat as 503).
	Get(ctx context.Context, token string) (*Session, error)

	// Delete removes the session by token. Gains a userID parameter in
	// Sprint 3 so the implementation can SREM from user_sessions:<userID>
	// alongside the session key DEL, maintaining the per-user index without
	// a two-roundtrip read-then-delete pattern. Idempotent.
	Delete(ctx context.Context, userID, token string) error

	// ListByUser returns all active sessions for a user by reading the
	// user_sessions:<userID> SET and multi-GETing each session value. Stale
	// SET entries (whose session keys have expired) are filtered out. Each
	// returned entry carries the opaque token alongside the session metadata
	// so callers can issue per-device Delete calls.
	ListByUser(ctx context.Context, userID string) ([]*SessionWithToken, error)

	// DeleteAllForUser destroys every session for a given user — used by
	// disable, delete, reset-password, and nuclear force-terminate flows.
	DeleteAllForUser(ctx context.Context, userID string) error
}

// ErrNotFound is returned by Get when the session token does not exist in Valkey.
var ErrNotFound = errors.New("session: not found")

// NewValkeyStore constructs the production implementation.
// ttl is the absolute TTL refreshed on every Get.
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

// Create implements Store.Create on top of Valkey.
//
// Pipeline note: SET, SADD, and EXPIRE are issued as a pipeline (batched),
// not as a MULTI/EXEC transaction. If a middle command fails (e.g., SET
// succeeds but SADD fails), the session key may exist without its entry
// in user_sessions:<user_id>. The session is still usable for
// authentication (Get doesn't touch the SET), but it won't appear in
// ListByUser and can't be force-terminated by the admin until its own
// TTL expires. Bounded blast radius by the session TTL (24h default).
// Acceptable trade-off for avoiding a distributed transaction layer.
func (s *valkeyStore) Create(ctx context.Context, userID, ipAddress, userAgent string) (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("session: generate token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(buf[:])

	now := time.Now().UTC()
	sess := Session{
		UserID:     userID,
		CreatedAt:  now,
		LastSeenAt: now,
		IPAddress:  ipAddress,
		UserAgent:  userAgent,
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

// Get implements Store.Get on top of Valkey.
//
// Pipeline note: the TTL slide for the session key and the
// user_sessions:<user_id> SET are issued in one pipeline. Under a
// non-fatal pipeline failure (logged as slog.Warn), the session key
// may be extended while the SET TTL is not, or vice versa. In the
// worst case, a user's entry in ListByUser may silently disappear
// before the session itself expires. The admin UI "active sessions"
// view degrades by showing an empty list; the session remains
// usable for authentication. Next successful Get re-extends both
// TTLs. If this becomes a real operational concern, split the
// pipeline into separate Set + Expire calls at the cost of an extra
// roundtrip.
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

	// Update LastSeenAt and slide the TTL in one SET command (replaces
	// Sprint 2's separate EXPIRE). Also refresh the user_sessions SET TTL
	// so it stays alive as long as any of its members are active.
	sess.LastSeenAt = time.Now().UTC()
	newPayload, err := json.Marshal(sess)
	if err != nil {
		return nil, fmt.Errorf("session: remarshal: %w", err)
	}
	pipe := s.client.Pipeline()
	pipe.Set(ctx, key, newPayload, s.ttl)
	pipe.Expire(ctx, userSessionsKey(sess.UserID), s.ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		// TTL slide failed but we have the session — return it with a WARN.
		// Matches Sprint 2's non-fatal TTL slide behavior.
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

	// Multi-GET via pipeline — one roundtrip for N commands.
	pipe := s.client.Pipeline()
	cmds := make([]*redis.StringCmd, len(tokens))
	for i, t := range tokens {
		cmds[i] = pipe.Get(ctx, sessionKey(t))
	}
	_, _ = pipe.Exec(ctx) // errors here are per-command; we check each cmd below

	sessions := make([]*SessionWithToken, 0, len(tokens))
	for i, cmd := range cmds {
		raw, err := cmd.Bytes()
		if errors.Is(err, redis.Nil) {
			// Stale SET entry — session key expired but the token is still in
			// the SET. Lazily skip; the entry will be cleaned up on the next
			// DeleteAllForUser or fall out naturally with SET TTL.
			continue
		}
		if err != nil {
			// Transient transport error on a per-key GET. Returning a partial
			// list would silently break the admin UI's force-terminate flow
			// (user might keep a session the admin thought they killed).
			// Surface the error and let the caller retry or degrade.
			return nil, fmt.Errorf("session: listbyuser get %s: %w", tokens[i], err)
		}
		var sess Session
		if err := json.Unmarshal(raw, &sess); err != nil {
			// Corrupt JSON is also not a "skip" case — log and surface.
			return nil, fmt.Errorf("session: listbyuser unmarshal %s: %w", tokens[i], err)
		}
		sessions = append(sessions, &SessionWithToken{Token: tokens[i], Session: sess})
	}
	return sessions, nil
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
