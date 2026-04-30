package session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestSession_AuditViewedInSession_RoundTrip(t *testing.T) {
	ctx := context.Background()
	store := newTestValkeyStore(t)

	tok, err := store.Create(ctx, "user-1", "127.0.0.1", "ua")
	if err != nil {
		t.Fatal(err)
	}

	s, err := store.Get(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	if s.AuditViewedInSession {
		t.Fatal("expected false on fresh session")
	}

	if err := store.MarkAuditViewed(ctx, tok); err != nil {
		t.Fatal(err)
	}
	s, err = store.Get(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	if !s.AuditViewedInSession {
		t.Fatal("expected true after MarkAuditViewed")
	}
}

func newTestValkeyStore(t *testing.T) Store {
	t.Helper()
	client := redis.NewClient(&redis.Options{Addr: "redis.invalid:6379", Protocol: 2})
	client.AddHook(newRedisMemoryHook())
	t.Cleanup(func() { _ = client.Close() })
	return NewValkeyStore(client, time.Hour)
}

type redisMemoryHook struct {
	mu   sync.Mutex
	data map[string]string
	ttl  map[string]time.Duration
}

func newRedisMemoryHook() *redisMemoryHook {
	return &redisMemoryHook{data: make(map[string]string), ttl: make(map[string]time.Duration)}
}

func (h *redisMemoryHook) DialHook(next redis.DialHook) redis.DialHook {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, errors.New("redis memory hook should intercept commands before dial")
	}
}

func (h *redisMemoryHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		return h.process(cmd)
	}
}

func (h *redisMemoryHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		for _, cmd := range cmds {
			if err := h.process(cmd); err != nil {
				return err
			}
		}
		return nil
	}
}

func (h *redisMemoryHook) process(cmd redis.Cmder) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	args := cmd.Args()
	if len(args) == 0 {
		return nil
	}

	switch strings.ToLower(fmt.Sprint(args[0])) {
	case "set":
		key := fmt.Sprint(args[1])
		h.data[key] = redisArgString(args[2])
		h.ttl[key] = time.Hour
		setStatus(cmd, "OK")
	case "get":
		key := fmt.Sprint(args[1])
		v, ok := h.data[key]
		if !ok {
			cmd.SetErr(redis.Nil)
			return redis.Nil
		}
		setString(cmd, v)
	case "sadd", "expire":
		setInt(cmd, 1)
	case "ttl":
		key := fmt.Sprint(args[1])
		if _, ok := h.data[key]; !ok {
			setDuration(cmd, -2*time.Second)
			return nil
		}
		ttl := h.ttl[key]
		if ttl <= 0 {
			ttl = time.Hour
		}
		setDuration(cmd, ttl)
	default:
		setStatus(cmd, "OK")
	}
	return nil
}

func setStatus(cmd redis.Cmder, val string) {
	if c, ok := cmd.(*redis.StatusCmd); ok {
		c.SetVal(val)
	}
}

func setString(cmd redis.Cmder, val string) {
	if c, ok := cmd.(*redis.StringCmd); ok {
		c.SetVal(val)
	}
}

func setInt(cmd redis.Cmder, val int64) {
	if c, ok := cmd.(*redis.IntCmd); ok {
		c.SetVal(val)
	}
}

func setDuration(cmd redis.Cmder, val time.Duration) {
	if c, ok := cmd.(*redis.DurationCmd); ok {
		c.SetVal(val)
	}
}

func redisArgString(v any) string {
	switch x := v.(type) {
	case []byte:
		return string(x)
	case string:
		return x
	default:
		return fmt.Sprint(x)
	}
}
