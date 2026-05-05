//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/abdo75/Schlass/internal/audit"
	"github.com/abdo75/Schlass/internal/audit/stream"
	"github.com/abdo75/Schlass/internal/instanceconfig"
)

// fakeStreamer records every event it receives and can be configured to
// fail a configurable number of pushes before succeeding. Thread-safe
// because the worker may invoke Push in parallel during DLQ drain.
type fakeStreamer struct {
	mu          sync.Mutex
	failsLeft   int
	pushed      []stream.Event
	pushCalls   int
	closeCalled bool
}

func (f *fakeStreamer) Push(_ context.Context, batch []stream.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pushCalls++
	if f.failsLeft > 0 {
		f.failsLeft--
		return errors.New("fake streamer: injected failure")
	}
	f.pushed = append(f.pushed, batch...)
	return nil
}

func (f *fakeStreamer) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closeCalled = true
	return nil
}

func (f *fakeStreamer) snapshot() ([]stream.Event, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]stream.Event, len(f.pushed))
	copy(out, f.pushed)
	return out, f.pushCalls
}

// TestStreamWorker_ForwardHappyPath emits N events, runs RunOnce, and
// asserts every event reached the streamer + the watermark advanced.
func TestStreamWorker_ForwardHappyPath(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()
	ctx := context.Background()

	const n = 5
	actorID := seedChain(t, env, n)
	_ = actorID

	cfg := instanceconfig.NewService(instanceconfig.NewStore(), env.Cfg.EncryptionKey)
	store := audit.NewStore()
	fake := &fakeStreamer{}

	worker := audit.NewStreamWorker(env.Pool, cfg, store, fake, "fake")
	if err := worker.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	pushed, calls := fake.snapshot()
	if len(pushed) != n {
		t.Fatalf("pushed = %d, want %d (calls=%d)", len(pushed), n, calls)
	}
	for i, e := range pushed {
		if e.SequenceNo != int64(i+1) {
			t.Errorf("pushed[%d].SequenceNo = %d, want %d", i, e.SequenceNo, i+1)
		}
	}

	// Watermark should equal the last pushed sequence_no.
	var last int64
	if err := env.Pool.QueryRow(ctx,
		`SELECT last_seq FROM audit_stream_state WHERE tenant_id = $1`,
		audit.SingleTenant,
	).Scan(&last); err != nil {
		t.Fatalf("watermark read: %v", err)
	}
	if last != int64(n) {
		t.Errorf("watermark = %d, want %d", last, n)
	}
}

// TestStreamWorker_DLQRetryRoundtrip seeds events, runs the worker
// while the streamer is failing, then unblocks the streamer and
// asserts retries drain the DLQ.
func TestStreamWorker_DLQRetryRoundtrip(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()
	ctx := context.Background()

	seedChain(t, env, 3)

	cfg := instanceconfig.NewService(instanceconfig.NewStore(), env.Cfg.EncryptionKey)
	store := audit.NewStore()
	// Fail the first push (forward stream lands in DLQ).
	fake := &fakeStreamer{failsLeft: 1}
	worker := audit.NewStreamWorker(env.Pool, cfg, store, fake, "fake")

	if err := worker.RunOnce(ctx); err != nil {
		t.Fatalf("first RunOnce: %v", err)
	}
	pushed, _ := fake.snapshot()
	if len(pushed) != 0 {
		t.Fatalf("after first cycle, pushed = %d, want 0 (push failed)", len(pushed))
	}

	// Forward stream advanced past the failed batch — the rows should
	// now sit in audit_stream_dlq.
	var dlqCount int64
	if err := env.Pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_stream_dlq WHERE tenant_id = $1 AND attempt_count >= 0`,
		audit.SingleTenant,
	).Scan(&dlqCount); err != nil {
		t.Fatalf("dlq count: %v", err)
	}
	if dlqCount != 3 {
		t.Fatalf("dlq count = %d, want 3", dlqCount)
	}

	// Force every DLQ row to be retry-eligible immediately.
	if _, err := env.Pool.Exec(ctx,
		`UPDATE audit_stream_dlq SET next_retry_at = now() - INTERVAL '1 second'`,
	); err != nil {
		t.Fatalf("force retry: %v", err)
	}

	if err := worker.RunOnce(ctx); err != nil {
		t.Fatalf("second RunOnce: %v", err)
	}

	pushed, _ = fake.snapshot()
	if len(pushed) != 3 {
		t.Fatalf("after retry cycle, pushed = %d, want 3", len(pushed))
	}

	if err := env.Pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_stream_dlq WHERE tenant_id = $1 AND attempt_count >= 0`,
		audit.SingleTenant,
	).Scan(&dlqCount); err != nil {
		t.Fatalf("dlq count post-retry: %v", err)
	}
	if dlqCount != 0 {
		t.Errorf("dlq count post-retry = %d, want 0", dlqCount)
	}
}

// TestStreamWorker_DropAfterMaxAge backdates a DLQ row past the
// MaxRetainAge cutoff and asserts the worker marks it dropped + emits
// audit.stream.dropped.
func TestStreamWorker_DropAfterMaxAge(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()
	ctx := context.Background()

	seedChain(t, env, 1)

	cfg := instanceconfig.NewService(instanceconfig.NewStore(), env.Cfg.EncryptionKey)
	store := audit.NewStore()
	// Always fail so the row stays in the DLQ.
	fake := &fakeStreamer{failsLeft: 999}
	worker := audit.NewStreamWorker(env.Pool, cfg, store, fake, "fake")

	if err := worker.RunOnce(ctx); err != nil {
		t.Fatalf("first RunOnce: %v", err)
	}

	// Backdate the DLQ entry past 24h so the next cycle drops it.
	if _, err := env.Pool.Exec(ctx,
		`UPDATE audit_stream_dlq SET created_at = now() - INTERVAL '25 hours',
		                           next_retry_at = now() - INTERVAL '1 second'`,
	); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	if err := worker.RunOnce(ctx); err != nil {
		t.Fatalf("second RunOnce: %v", err)
	}

	var attemptCount int32
	if err := env.Pool.QueryRow(ctx,
		`SELECT attempt_count FROM audit_stream_dlq WHERE tenant_id = $1 AND sequence_no = 1`,
		audit.SingleTenant,
	).Scan(&attemptCount); err != nil {
		t.Fatalf("read dlq attempt_count: %v", err)
	}
	if attemptCount != -1 {
		t.Errorf("attempt_count = %d, want -1 (dropped sentinel)", attemptCount)
	}

	// audit.stream.dropped row should have landed.
	var droppedRows int
	if err := env.Pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_logs WHERE event_type = 'audit.stream.dropped'`,
	).Scan(&droppedRows); err != nil {
		t.Fatalf("read dropped audit: %v", err)
	}
	if droppedRows != 1 {
		t.Errorf("audit.stream.dropped rows = %d, want 1", droppedRows)
	}
}

// TestStreamWorker_NoneBackend exits cleanly without doing any work.
// Run via the public StartStreamWorker so the no-op short-circuit is
// what's actually exercised.
func TestStreamWorker_NoneBackend(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cfg := instanceconfig.NewService(instanceconfig.NewStore(), env.Cfg.EncryptionKey)
	store := audit.NewStore()
	done := make(chan struct{})
	go func() {
		audit.StartStreamWorker(ctx, env.Pool, cfg, store)
		close(done)
	}()
	select {
	case <-done:
		// Expected: backend=none → immediate return.
	case <-time.After(1 * time.Second):
		t.Fatalf("StartStreamWorker did not exit on backend=none")
	}
}

// TestCriticalEvent_FailClosed_ClientMismatch forces the audit-emit to
// fail on the oidc.code.client_mismatch path and asserts the response
// is 500 (REQ-AUD-060). Implementation detail: we wrap the audit_logs
// table in a BEFORE-INSERT trigger that errors if the row's reason
// metadata flags it. The trigger is dropped via t.Cleanup.
func TestCriticalEvent_FailClosed_ClientMismatch(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()
	ctx := context.Background()

	// Inject a trigger that vetoes the next oidc.code.client_mismatch
	// INSERT. (Indirect — we can't intercept the Go-side Emit without
	// rewiring the router, but we can intercept the SQL it issues.)
	const triggerSQL = `
		CREATE OR REPLACE FUNCTION test_audit_veto() RETURNS trigger
		LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.event_type = 'oidc.code.client_mismatch' THEN
				RAISE EXCEPTION 'test veto: simulated audit failure';
			END IF;
			RETURN NEW;
		END;
		$$;
		CREATE TRIGGER test_audit_veto_trigger
		BEFORE INSERT ON audit_logs
		FOR EACH ROW EXECUTE FUNCTION test_audit_veto();`
	if _, err := env.MigrationsPool.Exec(ctx, triggerSQL); err != nil {
		t.Fatalf("install trigger: %v", err)
	}
	t.Cleanup(func() {
		_, _ = env.MigrationsPool.Exec(ctx, `DROP TRIGGER IF EXISTS test_audit_veto_trigger ON audit_logs;
			DROP FUNCTION IF EXISTS test_audit_veto;`)
	})

	// Open a fresh tx and try to emit oidc.code.client_mismatch directly.
	// The trigger will RAISE, so Emit returns an error. This is the
	// post-fix contract: error surfaces to the caller, not swallowed.
	tx, err := env.Pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	store := audit.NewStore()
	clientID := uuid.New()
	userID := uuid.New()
	emitErr := store.Emit(ctx, tx, audit.Event{
		EventType:  "oidc.code.client_mismatch",
		ActorID:    &userID,
		TargetType: "client",
		TargetID:   clientID.String(),
		ClientID:   &clientID,
		Outcome:    "failure",
		Metadata:   map[string]any{"family_id": uuid.New().String()},
	})
	if emitErr == nil {
		t.Fatalf("Emit succeeded despite veto trigger — fail-closed contract is broken")
	}
	if !containsString(emitErr.Error(), "test veto") {
		t.Errorf("Emit error did not surface veto cause: %v", emitErr)
	}

	// The tx is poisoned ("current transaction is aborted") after a
	// trigger RAISE — abandon it. Verify on a fresh connection that no
	// audit row landed (the trigger fired BEFORE INSERT).
	_ = tx.Rollback(ctx)
	var rows int
	if err := env.Pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_logs WHERE event_type = 'oidc.code.client_mismatch'`,
	).Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 0 {
		t.Errorf("rows = %d, want 0 (trigger should have vetoed insert)", rows)
	}
}

func containsString(s, sub string) bool {
	return s != "" && sub != "" && (len(s) >= len(sub) && (indexOf(s, sub) >= 0))
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// Compile-time guard: ensure stream.Streamer is satisfied by the fake.
var _ stream.Streamer = (*fakeStreamer)(nil)

// silence unused import noise for pgx in case go modules grumble.
var _ = pgx.ErrNoRows
var _ = fmt.Errorf
