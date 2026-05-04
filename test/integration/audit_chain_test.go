//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/abdo75/Schlass/internal/audit"
)

// emitOne wraps the per-tx emit dance. Callers pass the event;
// helper opens a tx, emits, commits.
func emitOne(t *testing.T, env *TestEnv, store *audit.Store, e audit.Event) {
	t.Helper()
	ctx := context.Background()
	tx, err := env.Pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.Emit(ctx, tx, e); err != nil {
		t.Fatalf("emit: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// seedChain emits N rows in sequence via Emit. Returns the actorID it
// used so callers can correlate.
func seedChain(t *testing.T, env *TestEnv, n int) uuid.UUID {
	t.Helper()
	store := audit.NewStore()
	actorID := uuid.New()
	for i := 0; i < n; i++ {
		emitOne(t, env, store, audit.Event{
			EventType:  "login.succeeded",
			Outcome:    "success",
			ActorID:    &actorID,
			TargetType: "user",
			TargetID:   actorID.String(),
			Metadata:   map[string]any{"i": i},
		})
	}
	return actorID
}

// TestChain_GoodFixture_RewalksClean inserts 100 rows via Emit and
// runs Verify; the report should be clean (no Mismatch, no Gap).
func TestChain_GoodFixture_RewalksClean(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	seedChain(t, env, 100)

	report, err := audit.Verify(context.Background(), env.Pool, audit.VerifyOptions{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.Mismatch != nil {
		t.Fatalf("clean chain reported mismatch: seq=%d expected=%s got=%s",
			report.Mismatch.SequenceNo, report.Mismatch.ExpectedHex, report.Mismatch.GotHex)
	}
	if report.Gap != nil {
		t.Fatalf("clean chain reported gap: missing seq=%d", report.Gap.MissingSequenceNo)
	}
	if report.RowsChecked != 100 {
		t.Fatalf("rows_checked = %d, want 100", report.RowsChecked)
	}
}

// TestChain_TamperedRow_VerifierReportsBreakAtRow tampers with row 50
// (a metadata UPDATE via the migrations role, since schlass_app has no
// UPDATE permission on audit_logs). The verifier must detect the
// mismatch at sequence_no=50 — the row's stored row_hash no longer
// matches the canonical-JSON re-derivation of the (now-altered) row.
func TestChain_TamperedRow_VerifierReportsBreakAtRow(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	seedChain(t, env, 100)

	// Tamper using the migrations pool — schlass_app has no UPDATE
	// privilege on audit_logs (RLS enforces the audit-of-audit
	// guarantee that the app role cannot rewrite history).
	if _, err := env.MigrationsPool.Exec(context.Background(),
		`UPDATE audit_logs SET metadata = metadata || '{"tampered": true}'::jsonb
		 WHERE sequence_no = 50`); err != nil {
		t.Fatalf("tamper UPDATE: %v", err)
	}

	report, err := audit.Verify(context.Background(), env.Pool, audit.VerifyOptions{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.Mismatch == nil {
		t.Fatalf("expected mismatch, got clean report (rows_checked=%d)", report.RowsChecked)
	}
	if report.Mismatch.SequenceNo != 50 {
		t.Fatalf("mismatch at seq=%d, want 50", report.Mismatch.SequenceNo)
	}
	if report.Mismatch.ExpectedHex == report.Mismatch.GotHex {
		t.Fatalf("expected != got but the hex strings are equal — bug in mismatch reporting")
	}
}

// TestChain_TruncatedRow_VerifierReportsGap deletes row 50 and
// asserts the verifier reports a gap. This protects against silent
// row removal — even if the attacker has DELETE privilege somehow,
// the missing sequence_no shows up.
func TestChain_TruncatedRow_VerifierReportsGap(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	seedChain(t, env, 100)

	if _, err := env.MigrationsPool.Exec(context.Background(),
		`DELETE FROM audit_logs WHERE sequence_no = 50`); err != nil {
		t.Fatalf("delete: %v", err)
	}

	report, err := audit.Verify(context.Background(), env.Pool, audit.VerifyOptions{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.Gap == nil {
		t.Fatalf("expected gap, got: mismatch=%+v rows=%d", report.Mismatch, report.RowsChecked)
	}
	if report.Gap.MissingSequenceNo != 50 {
		t.Fatalf("gap at seq=%d, want 50", report.Gap.MissingSequenceNo)
	}
	if report.Gap.LastSeenSequenceNo != 49 {
		t.Fatalf("last seen = %d, want 49", report.Gap.LastSeenSequenceNo)
	}
}

// TestChain_ConcurrentEmits_NoGapsNoForks spawns 20 goroutines, each
// opening its own tx and emitting an event. The advisory lock in
// chain.Append serialises the per-tenant inserts; without it, two
// goroutines could read the same chain head and produce a fork (two
// rows with the same prev_hash but different sequence_no).
//
// Asserts: (a) all 20 rows present, (b) sequence_no values 1..20
// with no gaps, (c) Verify re-walks cleanly.
func TestChain_ConcurrentEmits_NoGapsNoForks(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	const N = 20
	store := audit.NewStore()
	actorID := uuid.New()

	var wg sync.WaitGroup
	errs := make(chan error, N)
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func(i int) {
			defer wg.Done()
			ctx := context.Background()
			tx, err := env.Pool.Begin(ctx)
			if err != nil {
				errs <- err
				return
			}
			defer func() { _ = tx.Rollback(ctx) }()
			if err := store.Emit(ctx, tx, audit.Event{
				EventType:  "login.succeeded",
				Outcome:    "success",
				ActorID:    &actorID,
				TargetType: "user",
				TargetID:   actorID.String(),
				Metadata:   map[string]any{"goroutine": i},
			}); err != nil {
				errs <- err
				return
			}
			if err := tx.Commit(ctx); err != nil {
				errs <- err
				return
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent emit error: %v", err)
		}
	}

	// (a) 20 rows present.
	var count int
	if err := env.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_logs`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != N {
		t.Fatalf("rows = %d, want %d", count, N)
	}

	// (b) sequence_no contiguous from 1.
	var minSeq, maxSeq, distinct int64
	if err := env.Pool.QueryRow(context.Background(),
		`SELECT MIN(sequence_no), MAX(sequence_no), COUNT(DISTINCT sequence_no) FROM audit_logs`).
		Scan(&minSeq, &maxSeq, &distinct); err != nil {
		t.Fatalf("seq stats: %v", err)
	}
	if minSeq != 1 {
		t.Fatalf("min seq = %d, want 1", minSeq)
	}
	if maxSeq != int64(N) {
		t.Fatalf("max seq = %d, want %d", maxSeq, N)
	}
	if distinct != int64(N) {
		t.Fatalf("distinct seq = %d, want %d (forks/dupes detected)", distinct, N)
	}

	// (c) chain re-walks cleanly.
	report, err := audit.Verify(context.Background(), env.Pool, audit.VerifyOptions{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.Mismatch != nil {
		t.Fatalf("verify mismatch at seq=%d", report.Mismatch.SequenceNo)
	}
	if report.Gap != nil {
		t.Fatalf("verify gap at seq=%d", report.Gap.MissingSequenceNo)
	}
}

// TestChain_LegacyRowsAcceptedAsOpaque inserts a row directly via the
// migrations pool with the sentinel legacy hash (mimicking pre-M3
// rows that the migration backfill produced). Then emits a fresh
// chain row via Emit and asserts Verify rewalks cleanly across the
// boundary.
//
// This reproduces the M3 cutover: the migration's UPDATE leaves
// pre-existing rows with a deterministic but opaque row_hash; new
// emits read the legacy row's row_hash as their prev_hash and link
// from there.
func TestChain_LegacyRowsAcceptedAsOpaque(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	// Insert a legacy-shaped row directly via the migrations pool.
	// Bypasses chain.Append on purpose — this is what the M3 backfill
	// produced for pre-existing rows.
	legacyID := uuid.New()
	legacyHash := sha256.Sum256([]byte("legacy:" + legacyID.String()))
	if _, err := env.MigrationsPool.Exec(context.Background(),
		`INSERT INTO audit_logs (
		    id, event_type, outcome, schema_version,
		    actor_type, tenant_id, source_service,
		    sequence_no, prev_hash, row_hash
		 ) VALUES ($1, 'login.succeeded', 'success', 1,
		           'system', '00000000-0000-0000-0000-000000000000', 'auth',
		           nextval('audit_logs_seq'), NULL, $2)`,
		legacyID, legacyHash[:]); err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}

	// Emit a new M3-shaped row; should link cleanly off the legacy row.
	store := audit.NewStore()
	emitOne(t, env, store, audit.Event{
		EventType: "login.succeeded",
		Outcome:   "success",
		Metadata:  map[string]any{"after_legacy": true},
	})

	// Verifier accepts the legacy row opaquely and re-derives the M3
	// row, both should pass.
	report, err := audit.Verify(context.Background(), env.Pool, audit.VerifyOptions{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.Mismatch != nil {
		t.Fatalf("verifier flagged legacy/M3 boundary at seq=%d (expected=%s got=%s)",
			report.Mismatch.SequenceNo, report.Mismatch.ExpectedHex, report.Mismatch.GotHex)
	}
	if report.Gap != nil {
		t.Fatalf("verifier reported gap at seq=%d", report.Gap.MissingSequenceNo)
	}
	if report.RowsChecked != 2 {
		t.Fatalf("rows_checked = %d, want 2", report.RowsChecked)
	}
}

func TestChain_PseudonymizedRowsAcceptedAsSentinel(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	actorID := seedChain(t, env, 3)
	store := audit.NewStore()
	rows, err := store.PseudonymizeUser(context.Background(), env.Pool, actorID)
	if err != nil {
		t.Fatalf("pseudonymize: %v", err)
	}
	if rows != 3 {
		t.Fatalf("pseudonymized rows = %d, want 3", rows)
	}

	var id uuid.UUID
	var rowHash []byte
	if err := env.Pool.QueryRow(context.Background(),
		`SELECT id, row_hash FROM audit_logs WHERE metadata->>'pseudonymized_at' IS NOT NULL ORDER BY sequence_no LIMIT 1`).
		Scan(&id, &rowHash); err != nil {
		t.Fatalf("read pseudonymized row: %v", err)
	}
	if !bytes.Equal(rowHash, audit.PseudonymizedRowHash(id)) {
		t.Fatalf("row_hash is not pseudonymized sentinel")
	}

	report, err := audit.Verify(context.Background(), env.Pool, audit.VerifyOptions{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.Mismatch != nil || report.Gap != nil {
		t.Fatalf("pseudonymized chain not clean: mismatch=%+v gap=%+v", report.Mismatch, report.Gap)
	}
}

// TestChain_RolledBackEmitDoesNotLeakSequenceGap regresses the
// false-positive Gap pathway that surfaced when sequence_no was
// allocated via `nextval`. Postgres sequences advance outside the
// enclosing tx, so a rolled-back emit used to burn a sequence number
// and the next committed emit would carry sequence_no=N+2, prompting
// audit.Verify to report Gap{MissingSequenceNo: N+1} on an honest
// chain.
//
// The fix: Append reads the head + computes next = head.seq+1 inside
// the per-tenant advisory lock, all in the same tx as the INSERT —
// rollback leaves no scar. This test enforces that contract.
func TestChain_RolledBackEmitDoesNotLeakSequenceGap(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	store := audit.NewStore()
	actorID := uuid.New()
	ctx := context.Background()

	// Tx A: emit 1 row, commit. Expect sequence_no=1.
	emitOne(t, env, store, audit.Event{
		EventType:  "login.succeeded",
		Outcome:    "success",
		ActorID:    &actorID,
		TargetType: "user",
		TargetID:   actorID.String(),
		Metadata:   map[string]any{"tx": "a"},
	})
	var seqA int64
	if err := env.Pool.QueryRow(ctx,
		`SELECT sequence_no FROM audit_logs WHERE metadata->>'tx' = 'a'`).Scan(&seqA); err != nil {
		t.Fatalf("read seq A: %v", err)
	}
	if seqA != 1 {
		t.Fatalf("tx A sequence_no = %d, want 1", seqA)
	}

	// Tx B: emit 1 row, ROLLBACK. The sequence_no allocation must not
	// persist past rollback.
	{
		tx, err := env.Pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin B: %v", err)
		}
		if err := store.Emit(ctx, tx, audit.Event{
			EventType:  "login.succeeded",
			Outcome:    "success",
			ActorID:    &actorID,
			TargetType: "user",
			TargetID:   actorID.String(),
			Metadata:   map[string]any{"tx": "b"},
		}); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("emit B: %v", err)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatalf("rollback B: %v", err)
		}
	}

	// Tx C: emit 1 row, commit. Expect sequence_no=2 (NOT 3).
	emitOne(t, env, store, audit.Event{
		EventType:  "login.succeeded",
		Outcome:    "success",
		ActorID:    &actorID,
		TargetType: "user",
		TargetID:   actorID.String(),
		Metadata:   map[string]any{"tx": "c"},
	})
	var seqC int64
	if err := env.Pool.QueryRow(ctx,
		`SELECT sequence_no FROM audit_logs WHERE metadata->>'tx' = 'c'`).Scan(&seqC); err != nil {
		t.Fatalf("read seq C: %v", err)
	}
	if seqC != 2 {
		t.Fatalf("tx C sequence_no = %d, want 2 (rolled-back tx B leaked a sequence gap)", seqC)
	}

	// Verify the chain — must NOT report a gap.
	report, err := audit.Verify(ctx, env.Pool, audit.VerifyOptions{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.Gap != nil {
		t.Fatalf("verify reported false-positive gap at seq=%d after rolled-back emit",
			report.Gap.MissingSequenceNo)
	}
	if report.Mismatch != nil {
		t.Fatalf("verify reported mismatch at seq=%d", report.Mismatch.SequenceNo)
	}
	if report.RowsChecked != 2 {
		t.Fatalf("rows_checked = %d, want 2", report.RowsChecked)
	}
}

// TestChain_VerifySmoke is the CI-side smoke check the spec asks for in
// Step 7: seed a small chain and assert Verify is clean. Lives in the
// existing integration suite so it runs on every `make test` without a
// new Makefile target.
func TestChain_VerifySmoke(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	seedChain(t, env, 5)

	report, err := audit.Verify(context.Background(), env.Pool, audit.VerifyOptions{
		// since-cutoff exercise: setting Since to a past timestamp
		// should not change the report on a clean chain.
		Since: time.Now().Add(-1 * time.Hour),
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.Mismatch != nil || report.Gap != nil {
		t.Fatalf("smoke: dirty report on freshly-seeded chain: %+v", report)
	}
}
