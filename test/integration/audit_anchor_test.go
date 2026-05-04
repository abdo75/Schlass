//go:build integration

package integration

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/abdo75/Schlass/internal/audit"
	"github.com/abdo75/Schlass/internal/audit/anchor"
	"github.com/abdo75/Schlass/internal/instanceconfig"
)

func TestAppendFileAnchor_SubmitVerifyJSONL(t *testing.T) {
	dir := t.TempDir()
	a := anchor.NewAppendFile(dir)
	ctx := context.Background()
	heads := []anchor.ChainHead{
		{TenantID: uuid.New(), SequenceNo: 1, RowHash: []byte("hash-1"), AnchoredAt: time.Now().UTC()},
		{TenantID: uuid.New(), SequenceNo: 2, RowHash: []byte("hash-2"), AnchoredAt: time.Now().UTC()},
		{TenantID: uuid.New(), SequenceNo: 3, RowHash: []byte("hash-3"), AnchoredAt: time.Now().UTC()},
	}
	for _, head := range heads {
		proof, err := a.Submit(ctx, head)
		if err != nil {
			t.Fatalf("submit: %v", err)
		}
		if proof.Backend != anchor.AppendFileBackend {
			t.Fatalf("backend = %q, want %q", proof.Backend, anchor.AppendFileBackend)
		}
		if err := a.Verify(ctx, head, proof); err != nil {
			t.Fatalf("verify: %v", err)
		}
	}

	matches, err := filepath.Glob(filepath.Join(dir, "anchors-*.jsonl"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("anchor files = %d, want 1", len(matches))
	}
	f, err := os.Open(matches[0])
	if err != nil {
		t.Fatalf("open anchors file: %v", err)
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	lines := 0
	for scanner.Scan() {
		lines++
		var rec map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			t.Fatalf("line %d json: %v", lines, err)
		}
		if rec["tenant_id"] == "" || rec["row_hash"] == "" {
			t.Fatalf("line %d missing anchor fields: %#v", lines, rec)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan anchors file: %v", err)
	}
	if lines != 3 {
		t.Fatalf("jsonl lines = %d, want 3", lines)
	}
}

func TestAnchorJob_AppendFilePopulatesProofsAndEmitsAudit(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()
	ctx := context.Background()
	seedChain(t, env, 3)
	dir := t.TempDir()
	setConfig(t, env, "audit.anchor.backend", "appendfile")
	setConfig(t, env, "audit.anchor.path", dir)
	setConfig(t, env, "audit.anchor.events_per_anchor", 2)
	setConfig(t, env, "audit.anchor.interval_secs", 3600)

	job := audit.NewAnchorJob(env.Pool, env.BuildDeps().InstanceConfig, audit.NewStore())
	if err := job.RunOnce(ctx); err != nil {
		t.Fatalf("run once: %v", err)
	}

	var sequenceNo int64
	var backend, proofRef string
	if err := env.Pool.QueryRow(ctx,
		`SELECT sequence_no, backend, proof_ref FROM audit_anchors ORDER BY sequence_no`).Scan(&sequenceNo, &backend, &proofRef); err != nil {
		t.Fatalf("read anchor: %v", err)
	}
	if sequenceNo != 3 {
		t.Fatalf("anchored sequence = %d, want 3", sequenceNo)
	}
	if backend != anchor.AppendFileBackend || proofRef == "" {
		t.Fatalf("proof = (%q, %q), want appendfile with ref", backend, proofRef)
	}
	var auditRows int
	if err := env.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM audit_logs WHERE event_type = 'audit.anchor.created'`).Scan(&auditRows); err != nil {
		t.Fatalf("count audit event: %v", err)
	}
	if auditRows != 1 {
		t.Fatalf("audit.anchor.created rows = %d, want 1", auditRows)
	}
}

func setConfig(t *testing.T, env *TestEnv, key string, value any) {
	t.Helper()
	if err := instanceconfig.NewStore().Set(context.Background(), env.Pool, key, value); err != nil {
		t.Fatalf("set %s: %v", key, err)
	}
}

func TestAnchorJob_NoneBackendNoops(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()
	seedChain(t, env, 3)

	job := audit.NewAnchorJob(env.Pool, env.BuildDeps().InstanceConfig, audit.NewStore())
	if err := job.RunOnce(context.Background()); err != nil {
		t.Fatalf("run once none: %v", err)
	}
	var anchors int
	if err := env.Pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM audit_anchors`).Scan(&anchors); err != nil {
		t.Fatalf("count anchors: %v", err)
	}
	if anchors != 0 {
		t.Fatalf("anchors = %d, want 0", anchors)
	}
}

func TestS3Anchor_EnvGated(t *testing.T) {
	bucket := os.Getenv("AUDIT_S3_BUCKET")
	if bucket == "" {
		t.Skip("AUDIT_S3_BUCKET unset")
	}
	ctx := context.Background()
	a, err := anchor.NewS3FromDefaultConfig(ctx, bucket, 365)
	if err != nil {
		t.Fatalf("new s3 anchor: %v", err)
	}
	head := anchor.ChainHead{TenantID: uuid.New(), SequenceNo: time.Now().UnixNano(), RowHash: []byte("s3-anchor-test"), AnchoredAt: time.Now().UTC()}
	proof, err := a.Submit(ctx, head)
	if err != nil {
		t.Fatalf("s3 submit: %v", err)
	}
	if err := a.Verify(ctx, head, proof); err != nil {
		t.Fatalf("s3 verify: %v", err)
	}
}

func TestGCSAnchor_EnvGated(t *testing.T) {
	bucket := os.Getenv("AUDIT_GCS_BUCKET")
	if bucket == "" {
		t.Skip("AUDIT_GCS_BUCKET unset")
	}
	ctx := context.Background()
	a, err := anchor.NewGCSFromDefaultConfig(ctx, bucket)
	if err != nil {
		t.Fatalf("new gcs anchor: %v", err)
	}
	head := anchor.ChainHead{TenantID: uuid.New(), SequenceNo: time.Now().UnixNano(), RowHash: []byte("gcs-anchor-test"), AnchoredAt: time.Now().UTC()}
	proof, err := a.Submit(ctx, head)
	if err != nil {
		t.Fatalf("gcs submit: %v", err)
	}
	if err := a.Verify(ctx, head, proof); err != nil {
		t.Fatalf("gcs verify: %v", err)
	}
}
