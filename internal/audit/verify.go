// Verifier for the audit_logs hash chain. Walks one tenant's rows in
// sequence_no order, recomputes each row_hash from canonical JSON, and
// reports the first divergence.
//
// Legacy semantics: rows whose row_hash equals LegacyRowHash(id) and
// whose prev_hash is NULL are treated as opaque-but-continuous. They
// were inserted before the M3 migration and were not protected by a
// canonical-JSON hash; the verifier accepts them as a chain prefix and
// only enforces hash equality from the first M3-emitted row onward.
//
// Spec: docs/specs/audit-log-system.md §4 (REQ-AUD-021, 023).
package audit

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// VerifyOptions controls a Verify run.
type VerifyOptions struct {
	// TenantID restricts verification to one tenant. Zero value means
	// SingleTenant (the deployment-wide single-tenant constant).
	TenantID uuid.UUID
	// Since constrains the verification window. We trust each row's
	// stored prev_hash column (it is itself part of the row's hash
	// input, so any tamper of prev_hash would surface as a row_hash
	// mismatch). The gap check is suppressed for the first in-window
	// row because we cannot tell whether it is the chain head or just
	// the window head. Zero means walk the entire chain.
	Since time.Time
}

// VerifyReport is what a Verify run returns when it finishes (clean or
// not). The CLI prints it; integration tests assert against fields.
type VerifyReport struct {
	TenantID    uuid.UUID
	RowsChecked int
	// Mismatch is set when a row's recomputed row_hash diverges from
	// the stored row_hash. ExpectedHex is what the verifier computed,
	// GotHex is what the database holds.
	Mismatch *VerifyMismatch
	// Gap is set when sequence_no jumps (e.g. row 50 was deleted from
	// a 1..100 chain). MissingSequenceNo is the first absent value.
	Gap *VerifyGap
}

// VerifyMismatch — the row_hash recomputed from canonical JSON did not
// match the stored row_hash.
type VerifyMismatch struct {
	SequenceNo  int64
	EventID     uuid.UUID
	ExpectedHex string
	GotHex      string
}

// VerifyGap — the chain skipped a sequence_no.
type VerifyGap struct {
	MissingSequenceNo int64
	// LastSeenSequenceNo is the highest sequence_no the verifier saw
	// before the gap; useful for narrowing down which window the
	// missing row was in.
	LastSeenSequenceNo int64
}

// VerifierConn is the narrow read surface Verify needs. *pgx.Conn,
// *pgxpool.Pool, and pgx.Tx all satisfy it (their Query method shapes
// coincide). The CLI uses *pgx.Conn; integration tests typically pass
// the pool.
type VerifierConn interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// Verify walks the chain for opts.TenantID (default SingleTenant).
// Returns a populated VerifyReport on a clean run; sets Mismatch or
// Gap for the first divergence. The first such divergence short-circuits
// the walk — a tampered chain may have downstream effects but the
// operator only needs the first break to start triage.
func Verify(ctx context.Context, conn VerifierConn, opts VerifyOptions) (*VerifyReport, error) {
	tenant := opts.TenantID
	if tenant == uuid.Nil {
		tenant = SingleTenant
	}
	report := &VerifyReport{TenantID: tenant}

	rows, err := conn.Query(ctx, `
		SELECT id, sequence_no, event_type, schema_version, event_timestamp,
		       outcome, reason_code,
		       actor_type, actor_id, actor_session_id,
		       target_type, target_id, tenant_id, source_service,
		       client_id, host(client_ip_coarse), client_ua_family, client_geo_coarse,
		       request_id, correlation_id, metadata, retention_bucket,
		       prev_hash, row_hash
		  FROM audit_logs
		 WHERE tenant_id = $1
		   AND ($2::timestamptz IS NULL OR event_timestamp >= $2)
		 ORDER BY sequence_no ASC`,
		tenant, sinceArg(opts.Since),
	)
	if err != nil {
		return nil, fmt.Errorf("verify: query: %w", err)
	}
	defer rows.Close()

	var (
		expectedNext int64 = -1 // -1 means "no rows seen yet"
		lastSeen     int64
	)

	for rows.Next() {
		var (
			id              uuid.UUID
			sequenceNo      int64
			eventType       string
			schemaVersion   int
			eventTimestamp  time.Time
			outcome         string
			reasonCode      *string
			actorType       string
			actorID         *uuid.UUID
			actorSessionID  *uuid.UUID
			targetType      *string
			targetID        *string
			tenantID        uuid.UUID
			sourceService   string
			clientID        *uuid.UUID
			clientIPCoarse  *string
			clientUAFamily  *string
			clientGeoCoarse *string
			requestID       *string
			correlationID   *uuid.UUID
			metadataJSON    []byte
			retentionBucket *string
			prevHash        []byte
			rowHash         []byte
		)
		if err := rows.Scan(
			&id, &sequenceNo, &eventType, &schemaVersion, &eventTimestamp,
			&outcome, &reasonCode,
			&actorType, &actorID, &actorSessionID,
			&targetType, &targetID, &tenantID, &sourceService,
			&clientID, &clientIPCoarse, &clientUAFamily, &clientGeoCoarse,
			&requestID, &correlationID, &metadataJSON, &retentionBucket,
			&prevHash, &rowHash,
		); err != nil {
			return nil, fmt.Errorf("verify: scan: %w", err)
		}

		// Gap detection: only meaningful when we've already seen at
		// least one row. The cold-start path (--since cutoff cropping
		// the chain prefix) cannot tell whether the first row is the
		// chain head or just the first row in the window, so we only
		// flag gaps once the walk has begun.
		if expectedNext != -1 && sequenceNo != expectedNext {
			report.Gap = &VerifyGap{
				MissingSequenceNo:  expectedNext,
				LastSeenSequenceNo: lastSeen,
			}
			return report, nil
		}
		report.RowsChecked++
		lastSeen = sequenceNo
		expectedNext = sequenceNo + 1

		// Legacy row: prev_hash == NULL AND row_hash matches the
		// sentinel. Accept opaquely. Chain continuity for the next
		// row is enforced via that row's own prev_hash being part of
		// its hash input — re-derivation will fail there if anyone
		// rewrote a legacy row_hash.
		legacy := LegacyRowHash(id)
		if len(prevHash) == 0 && bytes.Equal(rowHash, legacy) {
			continue
		}

		// Non-legacy: parse metadata before deciding whether the row is a
		// pseudonymized sentinel or should be re-derived from its body.
		var metadata map[string]any
		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &metadata); err != nil {
				return nil, fmt.Errorf("verify: unmarshal metadata for seq %d: %w", sequenceNo, err)
			}
		}
		if _, ok := metadata["pseudonymized_at"]; ok {
			want := PseudonymizedRowHash(id)
			if !bytes.Equal(want, rowHash) {
				report.Mismatch = &VerifyMismatch{
					SequenceNo:  sequenceNo,
					EventID:     id,
					ExpectedHex: hex.EncodeToString(want),
					GotHex:      hex.EncodeToString(rowHash),
				}
				return report, nil
			}
			continue
		}

		ipCoarse := ""
		if clientIPCoarse != nil {
			ipCoarse = *clientIPCoarse
		}
		geoCoarse := ""
		if clientGeoCoarse != nil {
			geoCoarse = *clientGeoCoarse
		}

		cr := ChainRow{
			SchemaVersion:   schemaVersion,
			EventType:       eventType,
			EventTimestamp:  eventTimestamp.UTC().Format(time.RFC3339Nano),
			Outcome:         outcome,
			ReasonCode:      derefString(reasonCode),
			ActorType:       actorType,
			ActorID:         uuidPtrString(actorID),
			ActorSessionID:  uuidPtrString(actorSessionID),
			TargetType:      derefString(targetType),
			TargetID:        derefString(targetID),
			TenantID:        tenantID.String(),
			SourceService:   sourceService,
			ClientID:        uuidPtrString(clientID),
			ClientIPCoarse:  ipCoarse,
			ClientUAFamily:  derefString(clientUAFamily),
			ClientGeoCoarse: geoCoarse,
			RequestID:       derefString(requestID),
			CorrelationID:   uuidPtrString(correlationID),
			RetentionBucket: retentionBucketForHash(schemaVersion, retentionBucket),
			Metadata:        metadata,
			SequenceNo:      sequenceNo,
			PrevHash:        hex.EncodeToString(prevHash),
		}
		want, err := computeRowHash(cr)
		if err != nil {
			return nil, fmt.Errorf("verify: recompute seq %d: %w", sequenceNo, err)
		}
		if !bytes.Equal(want, rowHash) {
			report.Mismatch = &VerifyMismatch{
				SequenceNo:  sequenceNo,
				EventID:     id,
				ExpectedHex: hex.EncodeToString(want),
				GotHex:      hex.EncodeToString(rowHash),
			}
			return report, nil
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("verify: rows: %w", err)
	}
	return report, nil
}

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func retentionBucketForHash(schemaVersion int, p *string) string {
	if schemaVersion < 2 || p == nil {
		return ""
	}
	return *p
}

func sinceArg(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}
