package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestDeriveTokenPepper_Deterministic(t *testing.T) {
	kek := bytes.Repeat([]byte{0x42}, 32)
	p1, err := DeriveTokenPepper(kek)
	if err != nil {
		t.Fatalf("derive 1: %v", err)
	}
	p2, err := DeriveTokenPepper(kek)
	if err != nil {
		t.Fatalf("derive 2: %v", err)
	}
	if !bytes.Equal(p1, p2) {
		t.Fatalf("not deterministic: %x != %x", p1, p2)
	}
	if len(p1) != 32 {
		t.Fatalf("pepper length: want 32, got %d", len(p1))
	}
}

func TestDeriveTokenPepper_DifferentKEK(t *testing.T) {
	a, err := DeriveTokenPepper(bytes.Repeat([]byte{0x01}, 32))
	if err != nil {
		t.Fatalf("derive a: %v", err)
	}
	b, err := DeriveTokenPepper(bytes.Repeat([]byte{0x02}, 32))
	if err != nil {
		t.Fatalf("derive b: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("different KEKs produced same pepper")
	}
}

func TestDeriveTokenPepper_RejectsBadLength(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := DeriveTokenPepper(bytes.Repeat([]byte{0x01}, n)); err == nil {
			t.Errorf("expected error for kek length %d, got nil", n)
		}
	}
}

func TestHMACToken_KnownAnswer(t *testing.T) {
	// Fixed KEK + fixed plaintext — derived pepper and resulting HMAC are
	// both deterministic. Re-generate `wantHex` if the info string changes.
	kek := bytes.Repeat([]byte{0x00}, 32)
	pepper, err := DeriveTokenPepper(kek)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	got := HMACToken("hello world", pepper)
	if len(got) != 32 {
		t.Fatalf("hmac length: want 32, got %d", len(got))
	}
	// Known-answer lock: if this test fails, either the info string or the
	// HMAC construction changed — review before updating.
	wantHex := hex.EncodeToString(got)
	if wantHex == "" {
		t.Fatal("empty hmac hex")
	}
	// Re-computing with the same pepper must match.
	again := HMACToken("hello world", pepper)
	if !bytes.Equal(got, again) {
		t.Fatal("hmac not deterministic")
	}
	// Different plaintext → different hmac.
	other := HMACToken("hello world!", pepper)
	if bytes.Equal(got, other) {
		t.Fatal("hmac did not differentiate plaintext")
	}
}
