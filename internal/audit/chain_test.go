package audit

import (
	"encoding/hex"
	"testing"

	"github.com/google/uuid"
)

// TestLegacyRowHash_Deterministic asserts the sentinel scheme used by
// the M3 backfill is byte-stable: same id in -> same hash out. The
// migration computes the same value via pgcrypto's digest() and the
// verifier accepts rows where the stored row_hash matches this output.
func TestLegacyRowHash_Deterministic(t *testing.T) {
	id := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	a := LegacyRowHash(id)
	b := LegacyRowHash(id)
	if hex.EncodeToString(a) != hex.EncodeToString(b) {
		t.Fatalf("non-deterministic legacy hash: %x vs %x", a, b)
	}
	// Spot-check the value is non-empty and the right length for sha256.
	if len(a) != 32 {
		t.Fatalf("legacy hash length = %d, want 32", len(a))
	}
}

// TestComputeRowHash_DependsOnPrevHash asserts changing prev_hash
// changes row_hash — the chain is in fact chained. If this test fails,
// row_hash is decoupled from prev_hash and tampering can re-link a
// chain segment without detection.
func TestComputeRowHash_DependsOnPrevHash(t *testing.T) {
	base := ChainRow{
		SchemaVersion:  1,
		EventType:      "login.succeeded",
		EventTimestamp: "2026-04-30T00:00:00Z",
		Outcome:        "success",
		ActorType:      "user",
		TenantID:       "00000000-0000-0000-0000-000000000000",
		SourceService:  "auth",
		SequenceNo:     1,
		PrevHash:       "",
	}
	withPrev := base
	withPrev.PrevHash = "deadbeef"

	a, err := computeRowHash(base)
	if err != nil {
		t.Fatalf("compute base: %v", err)
	}
	b, err := computeRowHash(withPrev)
	if err != nil {
		t.Fatalf("compute withPrev: %v", err)
	}
	if hex.EncodeToString(a) == hex.EncodeToString(b) {
		t.Fatalf("row_hash unchanged after prev_hash flip — chain not chained")
	}
}

// TestComputeRowHash_DependsOnEventType asserts changing event_type
// changes row_hash. Belt-and-suspenders: if a payload swap (login ->
// account.locked) leaves row_hash equal, the verifier can't detect
// content tampering.
func TestComputeRowHash_DependsOnEventType(t *testing.T) {
	base := ChainRow{
		SchemaVersion:  1,
		EventType:      "login.succeeded",
		EventTimestamp: "2026-04-30T00:00:00Z",
		Outcome:        "success",
		ActorType:      "user",
		TenantID:       "00000000-0000-0000-0000-000000000000",
		SourceService:  "auth",
		SequenceNo:     1,
	}
	twisted := base
	twisted.EventType = "account.locked"

	a, err := computeRowHash(base)
	if err != nil {
		t.Fatalf("compute base: %v", err)
	}
	b, err := computeRowHash(twisted)
	if err != nil {
		t.Fatalf("compute twisted: %v", err)
	}
	if hex.EncodeToString(a) == hex.EncodeToString(b) {
		t.Fatalf("row_hash unchanged after event_type flip — content not protected")
	}
}
