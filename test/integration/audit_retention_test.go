//go:build integration

package integration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/abdo75/Schlass/internal/audit"
	"github.com/abdo75/Schlass/internal/audit/retention"
	"github.com/abdo75/Schlass/internal/database"
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
	purgePool, err := database.NewPool(ctx, env.PurgeConnString)
	if err != nil {
		t.Fatalf("connect purge role: %v", err)
	}
	defer purgePool.Close()
	results, err := retention.Purge(ctx, purgePool, retention.PurgeOptions{
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

func TestAuditRetention_PurgeFunctionPrivilegeBoundary(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()

	appConn, err := pgx.Connect(ctx, env.AppConnString)
	if err != nil {
		t.Fatalf("connect app: %v", err)
	}
	defer func() { _ = appConn.Close(ctx) }()
	_, err = appConn.Exec(ctx, `SELECT * FROM audit_purge_expired('audit_logs_209901', 'detach_drop')`)
	if err == nil {
		t.Fatal("schlass_app unexpectedly executed audit_purge_expired")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("app execute error = %v, want 42501", err)
	}

	month := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	createAuditPartitions(t, env, month, month)
	purgeConn, err := pgx.Connect(ctx, env.PurgeConnString)
	if err != nil {
		t.Fatalf("connect purge runner: %v", err)
	}
	defer func() { _ = purgeConn.Close(ctx) }()
	var partitionName, action string
	var rows int64
	if err := purgeConn.QueryRow(ctx, `SELECT partition_name, action, rows_affected FROM audit_purge_expired('audit_logs_209901', 'detach_drop')`).
		Scan(&partitionName, &action, &rows); err != nil {
		t.Fatalf("purge runner execute: %v", err)
	}
	if partitionName != "audit_logs_209901" || action != "detach_drop" || rows != 0 {
		t.Fatalf("unexpected purge result: partition=%s action=%s rows=%d", partitionName, action, rows)
	}
}

func TestAuditRetention_SameAsAnchorAppendFileRecordsColdParquetHash(t *testing.T) {
	env := NewTestEnv(t)
	ctx := context.Background()
	now := time.Now().UTC()
	createAuditPartitions(t, env, now.AddDate(0, -18, 0), now)

	store := audit.NewStore()
	ts := now.AddDate(0, -18, 0)
	emitOne(t, env, store, audit.Event{
		EventType:      "login.succeeded",
		EventTimestamp: ts,
		Outcome:        "success",
		ActorType:      audit.ActorTypeSystem,
		Metadata:       map[string]any{"cold_anchor": true},
	})
	anchorDir := t.TempDir()
	setConfig(t, env, "audit.cold_tier.backend", "same_as_anchor")
	setConfig(t, env, "audit.anchor.backend", "appendfile")
	setConfig(t, env, "audit.anchor.path", anchorDir)

	purgePool, err := database.NewPool(ctx, env.PurgeConnString)
	if err != nil {
		t.Fatalf("connect purge role: %v", err)
	}
	defer purgePool.Close()
	outDir := t.TempDir()
	results, err := retention.Purge(ctx, purgePool, retention.PurgeOptions{
		OutputDir:      outDir,
		InstanceConfig: instanceconfig.NewService(instanceconfig.NewStore(), nil),
		Now:            now,
	})
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	var parquetPath, proofRef string
	for _, res := range results {
		if res.Action == "security_cold_exported" && res.RowsAffected > 0 {
			parquetPath = filepath.Join(outDir, res.PartitionName+".parquet")
			proofRef = res.ProofRef
			break
		}
	}
	if parquetPath == "" {
		t.Fatalf("no cold export result: %+v", results)
	}
	body, err := os.ReadFile(parquetPath)
	if err != nil {
		t.Fatalf("read parquet: %v", err)
	}
	wantHash := sha256.Sum256(body)
	if !strings.Contains(proofRef, "anchors-") {
		t.Fatalf("proof_ref = %q, want appendfile ref", proofRef)
	}
	assertAppendFileContainsHash(t, anchorDir, retention.SHA256Hex(wantHash[:]))
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
		if _, err := env.MigrationsPool.Exec(ctx, `GRANT SELECT, INSERT ON TABLE `+name+` TO audit_purge_runner`); err != nil {
			t.Fatalf("grant purge runner on %s: %v", name, err)
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

func assertAppendFileContainsHash(t *testing.T, dir, hash string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "anchors-*.jsonl"))
	if err != nil {
		t.Fatalf("glob anchors: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("no appendfile anchors written")
	}
	for _, match := range matches {
		f, err := os.Open(match)
		if err != nil {
			t.Fatalf("open %s: %v", match, err)
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			var rec map[string]any
			if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
				_ = f.Close()
				t.Fatalf("parse appendfile line: %v", err)
			}
			if rec["row_hash"] == hash {
				_ = f.Close()
				return
			}
		}
		if err := scanner.Err(); err != nil {
			_ = f.Close()
			t.Fatalf("scan %s: %v", match, err)
		}
		_ = f.Close()
	}
	t.Fatalf("appendfile missing row_hash %s", hash)
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
