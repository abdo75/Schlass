//go:build integration

package integration

import (
	"crypto/rand"
	"encoding/base64"
	"net/netip"
	"testing"
	"time"

	"github.com/abdo75/Schlass/internal/crypto"
	"github.com/abdo75/Schlass/internal/store"
)

func TestInvalidateOutstandingForUser_MarksUnusedUsed(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()

	uid := env.DirectCreateUser(t, "invalidate@example.com", "user")
	pepper, perr := crypto.DeriveTokenPepper(env.Cfg.EncryptionKey)
	if perr != nil {
		t.Fatalf("derive pepper: %v", perr)
	}
	ts := store.NewPasswordResetTokenStore(pepper)

	var raw [32]byte
	_, _ = rand.Read(raw[:])
	tok := base64.RawURLEncoding.EncodeToString(raw[:])

	if _, err := ts.Insert(t.Context(), env.Pool, uid, tok, 30*time.Minute, netip.Addr{}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	n, err := ts.InvalidateOutstandingForUser(t.Context(), env.Pool, uid)
	if err != nil {
		t.Fatalf("invalidate: %v", err)
	}
	if n != 1 {
		t.Fatalf("invalidated %d rows, want 1", n)
	}

	got, err := ts.GetByTokenForUpdate(t.Context(), env.Pool, tok)
	if err != nil {
		t.Fatalf("get after invalidate: %v", err)
	}
	if got.UsedAt == nil {
		t.Fatal("expected used_at to be set after InvalidateOutstandingForUser")
	}
}

func TestInvalidateOutstandingForUser_SkipsAlreadyUsed(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()

	uid := env.DirectCreateUser(t, "skip-used@example.com", "user")
	pepper, perr := crypto.DeriveTokenPepper(env.Cfg.EncryptionKey)
	if perr != nil {
		t.Fatalf("derive pepper: %v", perr)
	}
	ts := store.NewPasswordResetTokenStore(pepper)

	var raw [32]byte
	_, _ = rand.Read(raw[:])
	tok := base64.RawURLEncoding.EncodeToString(raw[:])
	id, err := ts.Insert(t.Context(), env.Pool, uid, tok, 30*time.Minute, netip.Addr{})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := ts.MarkUsed(t.Context(), env.Pool, id); err != nil {
		t.Fatalf("mark used: %v", err)
	}

	n, err := ts.InvalidateOutstandingForUser(t.Context(), env.Pool, uid)
	if err != nil {
		t.Fatalf("invalidate: %v", err)
	}
	if n != 0 {
		t.Fatalf("invalidated %d rows on an already-used token, want 0", n)
	}
}
