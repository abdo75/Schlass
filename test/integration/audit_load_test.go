//go:build integration && loadtest

// Audit load drill (REQ-AUD M10 Drill 1).
//
// Sustains a target events/sec rate against chain.Append for a configurable
// duration, then reports p50/p95/p99 latency. Default knobs match the M10
// drill spec (200 ev/s for 30 min) but are tunable via environment so the
// same test can serve a short smoke (~5 s) in routine runs and the full
// drill on demand.
//
// Run:
//
//	go test -tags='integration loadtest' \
//	  -run TestAuditLoad_SustainedRate \
//	  -timeout 45m ./test/integration/...
//
// Env knobs:
//
//	AUDIT_LOAD_RATE     events/sec target (default 200)
//	AUDIT_LOAD_DURATION run duration  (default 5s; spec-target = 30m)
//	AUDIT_LOAD_WORKERS  concurrent workers (default 8)

package integration

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/abdo75/Schlass/internal/audit"
)

func TestAuditLoad_SustainedRate(t *testing.T) {
	rate := envInt("AUDIT_LOAD_RATE", 200)
	duration := envDuration("AUDIT_LOAD_DURATION", 5*time.Second)
	workers := envInt("AUDIT_LOAD_WORKERS", 8)

	if rate <= 0 || workers <= 0 {
		t.Fatalf("invalid load knobs: rate=%d workers=%d", rate, workers)
	}

	env := NewTestEnv(t)
	defer env.Cleanup()

	store := audit.NewStore()
	actorID := uuid.New()

	// Token-bucket pacing: a single producer ticks at rate Hz, workers pull
	// tokens and emit. Decoupling pacing from worker count keeps the rate
	// stable independent of per-emit latency variance.
	tokens := make(chan struct{}, rate)
	done := make(chan struct{})
	latencies := make([]time.Duration, 0, rate*int(duration.Seconds())+rate)
	var latMu sync.Mutex
	var emitted, failed int64

	// Pacer.
	pacerStart := time.Now()
	go func() {
		ticker := time.NewTicker(time.Second / time.Duration(rate))
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				select {
				case tokens <- struct{}{}:
				default:
					// drop — workers fell behind; counted via missed-rate
					// derivation: expected = rate*duration; emitted+failed
					// will reveal shortfall.
				}
			}
		}
	}()

	// Workers.
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := context.Background()
			for {
				select {
				case <-done:
					return
				case <-tokens:
					t0 := time.Now()
					if err := emitOneLoad(ctx, env, store, actorID); err != nil {
						atomic.AddInt64(&failed, 1)
						continue
					}
					lat := time.Since(t0)
					atomic.AddInt64(&emitted, 1)
					latMu.Lock()
					latencies = append(latencies, lat)
					latMu.Unlock()
				}
			}
		}()
	}

	// Run for duration, then signal stop and join.
	time.Sleep(duration)
	close(done)
	wg.Wait()
	wallClock := time.Since(pacerStart)

	if atomic.LoadInt64(&emitted) == 0 {
		t.Fatalf("no events emitted — load harness wiring broken")
	}

	// Verify chain still walks cleanly after the burst.
	report, err := audit.Verify(context.Background(), env.Pool, audit.VerifyOptions{})
	if err != nil {
		t.Fatalf("post-load verify: %v", err)
	}
	if report.Mismatch != nil || report.Gap != nil {
		t.Fatalf("chain broke under load: mismatch=%+v gap=%+v rows=%d",
			report.Mismatch, report.Gap, report.RowsChecked)
	}

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	p := func(q float64) time.Duration {
		if len(latencies) == 0 {
			return 0
		}
		i := int(float64(len(latencies)) * q)
		if i >= len(latencies) {
			i = len(latencies) - 1
		}
		return latencies[i]
	}

	achieved := float64(emitted) / wallClock.Seconds()
	t.Logf("=== AUDIT LOAD DRILL ===")
	t.Logf("target_rate    %d ev/s", rate)
	t.Logf("duration       %s", duration)
	t.Logf("workers        %d", workers)
	t.Logf("emitted        %d", emitted)
	t.Logf("failed         %d", failed)
	t.Logf("wallclock      %s", wallClock)
	t.Logf("achieved_rate  %.1f ev/s", achieved)
	t.Logf("p50_latency    %s", p(0.50))
	t.Logf("p95_latency    %s", p(0.95))
	t.Logf("p99_latency    %s", p(0.99))
	t.Logf("p999_latency   %s", p(0.999))
	t.Logf("rows_verified  %d", report.RowsChecked)

	// Soft thresholds — fail only on egregious regressions so this stays
	// useful as a CI smoke. The point of the drill is the captured numbers,
	// not a tight pass/fail gate. Tighter SLOs live in the runbook.
	if achieved < float64(rate)*0.50 {
		t.Errorf("achieved rate %.1f ev/s < 50%% of target %d", achieved, rate)
	}
	if p(0.99) > 500*time.Millisecond {
		t.Errorf("p99 latency %s > 500ms — unexpected regression", p(0.99))
	}
}

func emitOneLoad(ctx context.Context, env *TestEnv, store *audit.Store, actorID uuid.UUID) error {
	tx, err := env.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.Emit(ctx, tx, audit.Event{
		EventType:  "login.succeeded",
		Outcome:    "success",
		ActorID:    &actorID,
		TargetType: "user",
		TargetID:   actorID.String(),
		Metadata:   map[string]any{"load": true},
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func envInt(k string, def int) int {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		panic(fmt.Sprintf("invalid %s=%q: %v", k, v, err))
	}
	return n
}

func envDuration(k string, def time.Duration) time.Duration {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		panic(fmt.Sprintf("invalid %s=%q: %v", k, v, err))
	}
	return d
}
