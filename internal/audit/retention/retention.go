// Package retention implements M5 cold-tier export and partition purge.
// CLIs are thin wrappers so integration tests can call this package directly.
package retention

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/xitongsys/parquet-go-source/local"
	"github.com/xitongsys/parquet-go/parquet"
	"github.com/xitongsys/parquet-go/writer"

	"github.com/abdo75/Schlass/internal/audit"
	"github.com/abdo75/Schlass/internal/database"
	"github.com/abdo75/Schlass/internal/instanceconfig"
)

type ExportOptions struct {
	Partition string
	Output    string
	Backend   string
}

type ExportResult struct {
	Path      string
	SHA256    []byte
	Rows      int64
	ProofRef  string
	Backend   string
	AnchorSeq int64
}

type PurgeOptions struct {
	DryRun          bool
	OutputDir       string
	OperationalDays int
	SecurityHotDays int
	ColdTierBackend string
	InstanceConfig  *instanceconfig.Service
	ConfigStore     *instanceconfig.Store
	Now             time.Time
}

type PurgeResult struct {
	PartitionName string
	Action        string
	RowsAffected  int64
	ProofRef      string
	Warning       string
}

type Partition struct {
	Name  string
	From  time.Time
	Until time.Time
}

type parquetAuditRow struct {
	ID              string `parquet:"name=id, type=BYTE_ARRAY, convertedtype=UTF8, encoding=PLAIN_DICTIONARY"`
	EventType       string `parquet:"name=event_type, type=BYTE_ARRAY, convertedtype=UTF8, encoding=PLAIN_DICTIONARY"`
	ActorID         string `parquet:"name=actor_id, type=BYTE_ARRAY, convertedtype=UTF8, encoding=PLAIN_DICTIONARY"`
	TargetType      string `parquet:"name=target_type, type=BYTE_ARRAY, convertedtype=UTF8, encoding=PLAIN_DICTIONARY"`
	TargetID        string `parquet:"name=target_id, type=BYTE_ARRAY, convertedtype=UTF8, encoding=PLAIN_DICTIONARY"`
	ClientID        string `parquet:"name=client_id, type=BYTE_ARRAY, convertedtype=UTF8, encoding=PLAIN_DICTIONARY"`
	Outcome         string `parquet:"name=outcome, type=BYTE_ARRAY, convertedtype=UTF8, encoding=PLAIN_DICTIONARY"`
	Metadata        string `parquet:"name=metadata, type=BYTE_ARRAY, convertedtype=UTF8, encoding=PLAIN_DICTIONARY"`
	CreatedAt       int64  `parquet:"name=created_at, type=INT64, convertedtype=TIMESTAMP_MILLIS"`
	SchemaVersion   int32  `parquet:"name=schema_version, type=INT32"`
	RecordedAt      int64  `parquet:"name=recorded_at, type=INT64, convertedtype=TIMESTAMP_MILLIS"`
	EventTimestamp  int64  `parquet:"name=event_timestamp, type=INT64, convertedtype=TIMESTAMP_MILLIS"`
	ReasonCode      string `parquet:"name=reason_code, type=BYTE_ARRAY, convertedtype=UTF8, encoding=PLAIN_DICTIONARY"`
	ActorType       string `parquet:"name=actor_type, type=BYTE_ARRAY, convertedtype=UTF8, encoding=PLAIN_DICTIONARY"`
	ActorSessionID  string `parquet:"name=actor_session_id, type=BYTE_ARRAY, convertedtype=UTF8, encoding=PLAIN_DICTIONARY"`
	TenantID        string `parquet:"name=tenant_id, type=BYTE_ARRAY, convertedtype=UTF8, encoding=PLAIN_DICTIONARY"`
	SourceService   string `parquet:"name=source_service, type=BYTE_ARRAY, convertedtype=UTF8, encoding=PLAIN_DICTIONARY"`
	ClientUAFamily  string `parquet:"name=client_ua_family, type=BYTE_ARRAY, convertedtype=UTF8, encoding=PLAIN_DICTIONARY"`
	ClientGeoCoarse string `parquet:"name=client_geo_coarse, type=BYTE_ARRAY, convertedtype=UTF8, encoding=PLAIN_DICTIONARY"`
	RequestID       string `parquet:"name=request_id, type=BYTE_ARRAY, convertedtype=UTF8, encoding=PLAIN_DICTIONARY"`
	CorrelationID   string `parquet:"name=correlation_id, type=BYTE_ARRAY, convertedtype=UTF8, encoding=PLAIN_DICTIONARY"`
	SequenceNo      int64  `parquet:"name=sequence_no, type=INT64"`
	PrevHash        string `parquet:"name=prev_hash, type=BYTE_ARRAY"`
	RowHash         string `parquet:"name=row_hash, type=BYTE_ARRAY"`
	ClientIPCoarse  string `parquet:"name=client_ip_coarse, type=BYTE_ARRAY, convertedtype=UTF8, encoding=PLAIN_DICTIONARY"`
	RetentionBucket string `parquet:"name=retention_bucket, type=BYTE_ARRAY, convertedtype=UTF8, encoding=PLAIN_DICTIONARY"`
}

var partitionNameRE = regexp.MustCompile(`^audit_logs_[0-9]{6}$`)

func ExportCold(ctx context.Context, q database.Querier, opts ExportOptions) (ExportResult, error) {
	if !partitionNameRE.MatchString(opts.Partition) {
		return ExportResult{}, fmt.Errorf("audit cold export: invalid partition %q", opts.Partition)
	}
	if opts.Output == "" {
		return ExportResult{}, errors.New("audit cold export: output path is required")
	}
	if err := os.MkdirAll(filepath.Dir(opts.Output), 0o750); err != nil {
		return ExportResult{}, fmt.Errorf("audit cold export: mkdir: %w", err)
	}
	fw, err := local.NewLocalFileWriter(opts.Output)
	if err != nil {
		return ExportResult{}, fmt.Errorf("audit cold export: open parquet: %w", err)
	}
	pw, err := writer.NewParquetWriter(fw, new(parquetAuditRow), 4)
	if err != nil {
		_ = fw.Close()
		return ExportResult{}, fmt.Errorf("audit cold export: parquet writer: %w", err)
	}
	pw.CompressionType = parquetCompression()

	rows, err := q.Query(ctx, fmt.Sprintf(`
		SELECT id::text, event_type, actor_id::text, target_type, target_id, client_id::text,
		       outcome, metadata::text, created_at, schema_version, recorded_at,
		       event_timestamp, reason_code, actor_type, actor_session_id::text,
		       tenant_id::text, source_service, client_ua_family, client_geo_coarse,
		       request_id, correlation_id::text, sequence_no, prev_hash, row_hash,
		       host(client_ip_coarse), retention_bucket
		  FROM %s
		 ORDER BY sequence_no ASC`, pgx.Identifier{opts.Partition}.Sanitize()))
	if err != nil {
		_ = pw.WriteStop()
		_ = fw.Close()
		return ExportResult{}, fmt.Errorf("audit cold export: query: %w", err)
	}
	defer rows.Close()
	var exported int64
	tenantMax := map[uuid.UUID]int64{}
	for rows.Next() {
		rec, tenantID, seq, err := scanParquetAuditRow(rows)
		if err != nil {
			_ = pw.WriteStop()
			_ = fw.Close()
			return ExportResult{}, err
		}
		if err := pw.Write(rec); err != nil {
			_ = pw.WriteStop()
			_ = fw.Close()
			return ExportResult{}, fmt.Errorf("audit cold export: write row: %w", err)
		}
		exported++
		if seq > tenantMax[tenantID] {
			tenantMax[tenantID] = seq
		}
	}
	if err := rows.Err(); err != nil {
		_ = pw.WriteStop()
		_ = fw.Close()
		return ExportResult{}, fmt.Errorf("audit cold export: rows: %w", err)
	}
	if err := pw.WriteStop(); err != nil {
		_ = fw.Close()
		return ExportResult{}, fmt.Errorf("audit cold export: close parquet writer: %w", err)
	}
	if err := fw.Close(); err != nil {
		return ExportResult{}, fmt.Errorf("audit cold export: close parquet: %w", err)
	}
	sum, err := fileSHA256(opts.Output)
	if err != nil {
		return ExportResult{}, err
	}
	anchorSeq := coldAnchorSequence(opts.Partition)
	backend := opts.Backend
	if backend == "" {
		backend = "local"
	}
	proofRef := opts.Output
	for tenantID := range tenantMax {
		if _, err := q.Exec(ctx, `
			INSERT INTO audit_anchors (tenant_id, sequence_no, row_hash, backend, proof_ref, anchored_at)
			VALUES ($1, $2, $3, $4, $5, now())
			ON CONFLICT (tenant_id, sequence_no) DO NOTHING`,
			tenantID, anchorSeq, sum, backend+":parquet", proofRef,
		); err != nil {
			return ExportResult{}, fmt.Errorf("audit cold export: insert anchor: %w", err)
		}
	}
	return ExportResult{Path: opts.Output, SHA256: sum, Rows: exported, ProofRef: proofRef, Backend: backend + ":parquet", AnchorSeq: anchorSeq}, nil
}

func Purge(ctx context.Context, pool *pgxpool.Pool, opts PurgeOptions) ([]PurgeResult, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	securityHotDays := opts.SecurityHotDays
	operationalDays := opts.OperationalDays
	backend := opts.ColdTierBackend
	if opts.InstanceConfig != nil {
		if securityHotDays <= 0 {
			v, err := opts.InstanceConfig.AuditRetentionSecurityHotDays(ctx, pool)
			if err != nil {
				return nil, err
			}
			securityHotDays = v
		}
		if operationalDays <= 0 {
			v, err := opts.InstanceConfig.AuditRetentionOperationalDays(ctx, pool)
			if err != nil {
				return nil, err
			}
			operationalDays = v
		}
		if backend == "" {
			v, err := opts.InstanceConfig.AuditColdTierBackend(ctx, pool)
			if err != nil {
				return nil, err
			}
			backend = v
		}
	}
	if securityHotDays <= 0 {
		securityHotDays = 365
	}
	if operationalDays <= 0 {
		operationalDays = 90
	}
	if backend == "" || backend == "same_as_anchor" {
		backend = "local"
	}
	if opts.OutputDir == "" {
		opts.OutputDir = filepath.Join(os.TempDir(), "schlass-audit-cold")
	}

	parts, err := ListPartitions(ctx, pool)
	if err != nil {
		return nil, err
	}
	var results []PurgeResult
	for _, part := range parts {
		switch {
		case part.Until.Before(now.AddDate(0, 0, -securityHotDays)):
			res, err := purgeSecurityPartition(ctx, pool, part, opts, backend)
			if err != nil {
				return results, err
			}
			results = append(results, res)
		case part.Until.Before(now.AddDate(0, 0, -operationalDays)):
			res, err := purgeOperationalPartition(ctx, pool, part, opts)
			if err != nil {
				return results, err
			}
			if res.Action != "" {
				results = append(results, res)
			}
		}
	}
	return results, nil
}

func ListPartitions(ctx context.Context, q database.Querier) ([]Partition, error) {
	rows, err := q.Query(ctx, `
		SELECT c.relname, pg_get_expr(c.relpartbound, c.oid)
		  FROM pg_partition_tree('audit_logs'::regclass) pt
		  JOIN pg_class c ON c.oid = pt.relid
		 WHERE pt.relid <> 'audit_logs'::regclass
		 ORDER BY c.relname`)
	if err != nil {
		return nil, fmt.Errorf("audit purge: list partitions: %w", err)
	}
	defer rows.Close()
	var parts []Partition
	for rows.Next() {
		var name, bound string
		if err := rows.Scan(&name, &bound); err != nil {
			return nil, err
		}
		from, until, err := parseBounds(bound)
		if err != nil {
			return nil, fmt.Errorf("audit purge: parse %s bounds %q: %w", name, bound, err)
		}
		parts = append(parts, Partition{Name: name, From: from, Until: until})
	}
	return parts, rows.Err()
}

func purgeSecurityPartition(ctx context.Context, pool *pgxpool.Pool, part Partition, opts PurgeOptions, backend string) (PurgeResult, error) {
	out := filepath.Join(opts.OutputDir, part.Name+".parquet")
	if opts.DryRun {
		return PurgeResult{PartitionName: part.Name, Action: "would_export_detach_drop", ProofRef: out}, nil
	}
	exp, err := ExportCold(ctx, pool, ExportOptions{Partition: part.Name, Output: out, Backend: backend})
	if err != nil {
		return PurgeResult{}, err
	}
	rows, err := dropPartition(ctx, pool, part.Name, "detach_drop")
	if err != nil {
		return PurgeResult{}, err
	}
	if err := emitPurgeEvent(ctx, pool, "security_cold_exported", part.Name, rows, exp.ProofRef); err != nil {
		return PurgeResult{}, err
	}
	return PurgeResult{PartitionName: part.Name, Action: "security_cold_exported", RowsAffected: rows, ProofRef: exp.ProofRef}, nil
}

func purgeOperationalPartition(ctx context.Context, pool *pgxpool.Pool, part Partition, opts PurgeOptions) (PurgeResult, error) {
	msg := "operational expiry is deferred to security hot-retention partition archival; row-level DELETE is forbidden"
	if !opts.DryRun {
		if err := emitPurgeEvent(ctx, pool, "operational_skipped_hot_chain", part.Name, 0, ""); err != nil {
			return PurgeResult{}, err
		}
	}
	return PurgeResult{PartitionName: part.Name, Action: "operational_skipped_hot_chain", Warning: msg}, nil
}

func dropPartition(ctx context.Context, q database.Querier, name, action string) (int64, error) {
	var partitionName, gotAction string
	var rows int64
	if err := q.QueryRow(ctx, `SELECT partition_name, action, rows_affected FROM audit_purge_expired($1, $2)`, name, action).
		Scan(&partitionName, &gotAction, &rows); err != nil {
		return 0, fmt.Errorf("audit purge: drop %s: %w", name, err)
	}
	return rows, nil
}

func emitPurgeEvent(ctx context.Context, pool *pgxpool.Pool, action, partition string, rows int64, proofRef string) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	meta := map[string]any{
		"action":         action,
		"partition_name": partition,
		"rows_affected":  rows,
	}
	if proofRef != "" {
		meta["proof_ref"] = proofRef
	}
	if err := audit.NewStore().Emit(ctx, tx, audit.Event{
		EventType:  "audit.purge.executed",
		Outcome:    "success",
		ActorType:  audit.ActorTypeService,
		TargetType: "audit_partition",
		TargetID:   partition,
		Metadata:   meta,
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func scanParquetAuditRow(rows pgx.Rows) (*parquetAuditRow, uuid.UUID, int64, error) {
	var (
		id, eventType, outcome, actorType, tenantID, sourceService, retentionBucket string
		actorID, targetType, targetID, clientID, metadata, reasonCode               *string
		actorSessionID, clientUAFamily, clientGeoCoarse, requestID                  *string
		correlationID, clientIPCoarse                                               *string
		createdAt, recordedAt, eventTimestamp                                       time.Time
		schemaVersion                                                               int32
		sequenceNo                                                                  int64
		prevHash, rowHash                                                           []byte
	)
	if err := rows.Scan(
		&id, &eventType, &actorID, &targetType, &targetID, &clientID,
		&outcome, &metadata, &createdAt, &schemaVersion, &recordedAt,
		&eventTimestamp, &reasonCode, &actorType, &actorSessionID,
		&tenantID, &sourceService, &clientUAFamily, &clientGeoCoarse,
		&requestID, &correlationID, &sequenceNo, &prevHash, &rowHash,
		&clientIPCoarse, &retentionBucket,
	); err != nil {
		return nil, uuid.Nil, 0, fmt.Errorf("audit cold export: scan: %w", err)
	}
	tid, err := uuid.Parse(tenantID)
	if err != nil {
		return nil, uuid.Nil, 0, err
	}
	return &parquetAuditRow{
		ID: id, EventType: eventType, ActorID: deref(actorID), TargetType: deref(targetType),
		TargetID: deref(targetID), ClientID: deref(clientID), Outcome: outcome, Metadata: deref(metadata),
		CreatedAt: millis(createdAt), SchemaVersion: schemaVersion,
		RecordedAt: millis(recordedAt), EventTimestamp: millis(eventTimestamp),
		ReasonCode: deref(reasonCode), ActorType: actorType, ActorSessionID: deref(actorSessionID),
		TenantID: tenantID, SourceService: sourceService, ClientUAFamily: deref(clientUAFamily),
		ClientGeoCoarse: deref(clientGeoCoarse), RequestID: deref(requestID), CorrelationID: deref(correlationID),
		SequenceNo: sequenceNo, PrevHash: string(prevHash), RowHash: string(rowHash),
		ClientIPCoarse: deref(clientIPCoarse), RetentionBucket: retentionBucket,
	}, tid, sequenceNo, nil
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func parseBounds(bound string) (time.Time, time.Time, error) {
	re := regexp.MustCompile(`FROM \('([^']+)'\) TO \('([^']+)'\)`)
	m := re.FindStringSubmatch(bound)
	if len(m) != 3 {
		return time.Time{}, time.Time{}, errors.New("unexpected partition bound")
	}
	from, err := parsePGTime(m[1])
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	until, err := parsePGTime(m[2])
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	return from, until, nil
}

func parsePGTime(s string) (time.Time, error) {
	layouts := []string{"2006-01-02 15:04:05-07", "2006-01-02 15:04:05-07:00", "2006-01-02"}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("parse time %q", s)
}

func millis(t time.Time) int64 {
	return t.UTC().UnixMilli()
}

func fileSHA256(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: output path is operator-provided CLI input.
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func coldAnchorSequence(partition string) int64 {
	suffix := strings.TrimPrefix(partition, "audit_logs_")
	n, err := strconv.ParseInt(suffix, 10, 64)
	if err != nil {
		return 0
	}
	return -n
}

func parquetCompression() parquet.CompressionCodec {
	return parquet.CompressionCodec_SNAPPY
}

func SHA256Hex(b []byte) string {
	return hex.EncodeToString(b)
}
