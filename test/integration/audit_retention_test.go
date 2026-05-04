//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/abdo75/Schlass/internal/audit"
	"github.com/abdo75/Schlass/internal/audit/retention"
	"github.com/abdo75/Schlass/internal/instanceconfig"
)

func TestAuditRetention_PurgeExportsColdPartitionsAndKeepsHotChainVerifiable(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()
	now := time.Now().UTC()
	createAuditPartitions(t, env, now.AddDate(0, -18, 0), now)

	store := audit.NewStore()
	for i := 18; i >= 0; i-- {
		ts := now.AddDate(0, -i, 0)
		eventType := "login.succeeded"
		if i == 4 {
			eventType = "audit.viewed"
		}
		emitOne(t, env, store, audit.Event{
			EventType:      eventType,
			EventTimestamp: ts,
			Outcome:        "success",
			ActorType:      audit.ActorTypeSystem,
			TargetType:     "audit_partition",
			TargetID:       ts.Format("200601"),
			Metadata:       map[string]any{"fixture_months_ago": i},
		})
	}

	outDir := t.TempDir()
	cfgStore := instanceconfig.NewStore()
	cfg := instanceconfig.NewService(cfgStore, nil)
	results, err := retention.Purge(ctx, env.Pool, retention.PurgeOptions{
		OutputDir:       outDir,
		InstanceConfig:  cfg,
		ConfigStore:     cfgStore,
		Now:             now,
		ColdTierBackend: "local",
	})
	if err != nil {
		t.Fatalf("purge: %v", err)
	}

	var exported, operationalSkipped int
	for _, res := range results {
		switch res.Action {
		case "security_cold_exported":
			exported++
			if res.RowsAffected == 0 {
				t.Fatalf("exported %s with zero rows", res.PartitionName)
			}
			if _, err := os.Stat(res.ProofRef); err != nil {
				t.Fatalf("stat exported parquet %s: %v", res.ProofRef, err)
			}
			assertAnchorHashMatchesFile(t, env, res.ProofRef)
		case "operational_skipped_hot_chain":
			operationalSkipped++
			if res.Warning == "" {
				t.Fatalf("operational skip without warning: %+v", res)
			}
		}
	}
	if exported == 0 {
		t.Fatalf("expected at least one security cold export, got results %+v", results)
	}
	if operationalSkipped == 0 {
		t.Fatalf("expected operational hot-chain skip, got results %+v", results)
	}

	var oldHotRows int
	if err := env.Pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_logs WHERE event_timestamp < $1`,
		now.AddDate(0, 0, -365),
	).Scan(&oldHotRows); err != nil {
		t.Fatalf("count old hot rows: %v", err)
	}
	if oldHotRows != 0 {
		t.Fatalf("old security rows still hot = %d, want 0", oldHotRows)
	}

	report, err := audit.Verify(ctx, env.Pool, audit.VerifyOptions{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.Mismatch != nil || report.Gap != nil {
		t.Fatalf("chain not clean after purge: mismatch=%+v gap=%+v", report.Mismatch, report.Gap)
	}
}

func createAuditPartitions(t *testing.T, env *TestEnv, start, end time.Time) {
	t.Helper()
	ctx := context.Background()
	month := time.Date(start.Year(), start.Month(), 1, 0, 0, 0, 0, time.UTC)
	last := time.Date(end.Year(), end.Month(), 1, 0, 0, 0, 0, time.UTC)
	for !month.After(last) {
		name := "audit_logs_" + month.Format("200601")
		next := month.AddDate(0, 1, 0)
		sql := fmt.Sprintf(
			`CREATE TABLE IF NOT EXISTS %s PARTITION OF audit_logs FOR VALUES FROM ('%s') TO ('%s')`,
			name, month.Format("2006-01-02"), next.Format("2006-01-02"),
		)
		if _, err := env.MigrationsPool.Exec(ctx, sql); err != nil {
			t.Fatalf("create partition %s: %v", name, err)
		}
		if _, err := env.MigrationsPool.Exec(ctx, `GRANT SELECT, INSERT ON TABLE `+name+` TO schlass_app`); err != nil {
			t.Fatalf("grant app on %s: %v", name, err)
		}
		if _, err := env.MigrationsPool.Exec(ctx, `REVOKE UPDATE, DELETE ON TABLE `+name+` FROM PUBLIC`); err != nil {
			t.Fatalf("revoke public on %s: %v", name, err)
		}
		if _, err := env.MigrationsPool.Exec(ctx, `GRANT DELETE ON TABLE `+name+` TO audit_purge`); err != nil {
			t.Fatalf("grant purge on %s: %v", name, err)
		}
		month = next
	}
}

func assertAnchorHashMatchesFile(t *testing.T, env *TestEnv, path string) {
	t.Helper()
	body, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read parquet: %v", err)
	}
	sum := sha256.Sum256(body)
	var rowHash []byte
	if err := env.Pool.QueryRow(context.Background(),
		`SELECT row_hash FROM audit_anchors WHERE proof_ref = $1 ORDER BY anchored_at DESC LIMIT 1`,
		path,
	).Scan(&rowHash); err != nil {
		t.Fatalf("read cold anchor: %v", err)
	}
	if !bytes.Equal(rowHash, sum[:]) {
		t.Fatalf("anchor hash mismatch for %s", path)
	}
}
