// Hash-chain layer for audit_logs. Every M3-or-later row carries:
//   - sequence_no: monotonic, computed transactionally as MAX(seq)+1
//     for the tenant inside the per-tenant advisory lock.
//   - prev_hash: row_hash of the immediately prior row in the same tenant
//     (NULL for the first row in a tenant + for legacy pre-M3 rows).
//   - row_hash: sha256 over the canonical JSON of the row's fields plus
//     prev_hash. row_hash itself is NOT in the input — REQ-AUD-012.
//
// Concurrency is serialised per-tenant via pg_advisory_xact_lock on
// hashtext(tenant_id). The advisory lock auto-releases at tx end, so
// callers don't need to remember to unlock. Locking on the int4 hash
// keeps the lock keyspace narrow even with many tenants.
//
// Sequence number allocation rationale: an earlier draft used
// `nextval('audit_logs_seq')` as both the column DEFAULT and the
// reservation call inside Append. Postgres sequences advance OUTSIDE
// the enclosing tx, so any business tx that aborted after Append
// returned would burn a sequence number — the next committed emit
// would then carry a non-contiguous sequence_no and Verify would
// report a false-positive Gap. The current implementation reads
// MAX(sequence_no)+1 for the tenant inside the advisory lock; the
// read+insert participate in the same tx, so a rollback leaves no
// gap. The audit_logs_seq sequence object is kept vestigial for
// migration back-compat (see 000006_audit_seq_transactional.up.sql).
//
// Verifier semantics for legacy rows: the M3 migration backfilled
// pre-M3 rows with row_hash = sha256('legacy:' || id::text) and
// prev_hash = NULL. Verify treats those rows as opaque (does not
// re-derive from canonical JSON) but DOES check that the chain becomes
// continuous from the first M3-emitted row onward.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/abdo75/Schlass/internal/audit/anchor"
	"github.com/abdo75/Schlass/internal/database"
	"github.com/abdo75/Schlass/internal/middleware"
)

// Chain wraps the hash-chain INSERT path. Stateless; safe to share.
type Chain struct{}

// chainRow mirrors the column-name set hashed into row_hash. JSON tag
// names MUST match the SQL column names exactly so a future
// cross-language verifier produces the same canonical bytes.
//
// row_hash is intentionally absent — REQ-AUD-012 forbids self-reference.
// id and recorded_at are also absent: id is assigned post-INSERT (no
// stable value at hash time) and recorded_at is the DB-side now() that
// could differ from event_timestamp by sub-millisecond — we hash the
// caller-supplied event_timestamp instead so the input is fully
// deterministic from the event payload.
type chainRow struct {
	SchemaVersion   int            `json:"schema_version"`
	EventType       string         `json:"event_type"`
	EventTimestamp  string         `json:"event_timestamp"`
	Outcome         string         `json:"outcome"`
	ReasonCode      string         `json:"reason_code,omitempty"`
	ActorType       string         `json:"actor_type"`
	ActorID         string         `json:"actor_id,omitempty"`
	ActorSessionID  string         `json:"actor_session_id,omitempty"`
	TargetType      string         `json:"target_type,omitempty"`
	TargetID        string         `json:"target_id,omitempty"`
	TenantID        string         `json:"tenant_id"`
	SourceService   string         `json:"source_service"`
	ClientID        string         `json:"client_id,omitempty"`
	ClientIPCoarse  string         `json:"client_ip_coarse,omitempty"`
	ClientUAFamily  string         `json:"client_ua_family,omitempty"`
	ClientGeoCoarse string         `json:"client_geo_coarse,omitempty"`
	RequestID       string         `json:"request_id,omitempty"`
	CorrelationID   string         `json:"correlation_id,omitempty"`
	RetentionBucket string         `json:"retention_bucket,omitempty"`
	Metadata        map[string]any `json:"metadata,omitempty"`
	SequenceNo      int64          `json:"sequence_no"`
	PrevHash        string         `json:"prev_hash,omitempty"` // hex-encoded; empty for first row
}

// computeRowHash returns sha256(canonical(chainRow)).
func computeRowHash(r chainRow) ([]byte, error) {
	encoded, err := Canonicalize(r)
	if err != nil {
		return nil, fmt.Errorf("chain: canonicalize: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return sum[:], nil
}

// LegacyRowHash is the sentinel scheme the M3 migration uses for rows
// inserted before the chain went live. Exposed so the verifier and
// integration tests can recognise the shape without re-deriving it.
//
// Spec: see the leading comment in 000005_audit_hash_chain.up.sql.
func LegacyRowHash(id uuid.UUID) []byte {
	sum := sha256.Sum256([]byte("legacy:" + id.String()))
	return sum[:]
}

// PseudonymizedRowHash is the sentinel scheme used when GDPR erasure mutates
// actor_id, target_id, and metadata.pseudonymized_at on existing audit rows.
func PseudonymizedRowHash(id uuid.UUID) []byte {
	sum := sha256.Sum256([]byte("pseudonymized:" + id.String()))
	return sum[:]
}

// Append serialises per-tenant emits, computes row_hash, and INSERTs.
// MUST run inside an existing transaction; the advisory lock survives
// only as long as the tx and is released on COMMIT or ROLLBACK.
//
// The function reads the current chain head (row_hash, sequence_no)
// inside the per-tenant advisory lock. The next sequence_no is
// head.sequence_no+1 (or 1 when no head exists). The MAX read and the
// INSERT participate in the same tx, so a rollback leaves the chain
// state unchanged — no burned sequence numbers, no false-positive
// Gap reports. The unique constraint on (tenant_id, sequence_no) is
// the belt-and-suspenders backstop if a future code path bypasses the
// lock.
func (c *Chain) Append(ctx context.Context, tx pgx.Tx, s *Store, e Event) error {
	// Default actor_type from ActorID presence so existing call sites
	// don't have to set it explicitly.
	actorType := e.ActorType
	if actorType == "" {
		if e.ActorID != nil {
			actorType = ActorTypeUser
		} else {
			actorType = ActorTypeSystem
		}
	}

	tenantID := e.TenantID
	if tenantID == uuid.Nil {
		tenantID = SingleTenant
	}

	spec, ok := Lookup(e.EventType)
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownEventType, e.EventType)
	}

	sourceService := e.SourceService
	if sourceService == "" {
		sourceService = sourceServiceFromEventType(e.EventType)
	}
	retentionBucket := e.RetentionBucket
	if retentionBucket == "" {
		retentionBucket = spec.RetentionBucket
	}
	if retentionBucket == "" {
		retentionBucket = BucketSecurity
	}

	// correlation_id mirroring (kept identical to pre-M3 store.Emit).
	correlationID := e.CorrelationID
	cidStr := middleware.CorrelationID(ctx)
	if correlationID == nil && cidStr != "" {
		if u, err := uuid.Parse(cidStr); err == nil {
			correlationID = &u
		}
	}
	metadata := e.Metadata
	if correlationID != nil {
		merged := make(map[string]any, len(metadata)+1)
		for k, v := range metadata {
			merged[k] = v
		}
		merged["correlation_id"] = correlationID.String()
		metadata = merged
	}

	// Apply REQ-AUD-031 IP coarsening per the Store's configured mode.
	coarseIP, geoCoarse := s.applyIPMode(e.IPAddress, e.ClientGeoCoarse)

	// Per-tenant advisory lock. Auto-releases on tx end. The hashtext
	// cast keeps the keyspace small even with many tenants.
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtext($1::text))`,
		tenantID.String(),
	); err != nil {
		return fmt.Errorf("chain: advisory lock: %w", err)
	}

	// Read the current chain head for this tenant. NULL prev_hash for
	// the first M3 emit — sentinel-backfilled rows have a row_hash so
	// the chain reads cleanly across the M3 cutover. We also pull the
	// head's sequence_no so Append can derive next_seq = head_seq + 1
	// transactionally (see package doc).
	var (
		prevHash []byte
		headSeq  int64
	)
	if err := tx.QueryRow(ctx,
		`SELECT row_hash, sequence_no FROM audit_logs WHERE tenant_id = $1
		 ORDER BY sequence_no DESC LIMIT 1`, tenantID).Scan(&prevHash, &headSeq); err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("chain: read head: %w", err)
		}
		prevHash = nil
		headSeq = 0
	}

	// event_timestamp: zero falls back to DB now(). For hashing purposes
	// we need the same value the column will hold AFTER read-back, so
	// we truncate to microsecond precision (Postgres TIMESTAMPTZ stores
	// microseconds; nanoseconds in a Go time.Time would round-trip lossy
	// and break the hash). The DB-side recorded_at remains the
	// audit-of-audit timestamp and is intentionally NOT in the hash
	// input.
	eventTimestamp := e.EventTimestamp
	if eventTimestamp.IsZero() {
		eventTimestamp = time.Now()
	}
	eventTimestamp = eventTimestamp.UTC().Truncate(time.Microsecond)

	// nullable column projections
	var (
		reasonCode      *string
		clientUAFamily  *string
		clientGeoCoarse *string
		requestID       *string
		ipAddress       *string
	)
	if e.ReasonCode != "" {
		reasonCode = &e.ReasonCode
	}
	if e.ClientUAFamily != "" {
		clientUAFamily = &e.ClientUAFamily
	}
	if geoCoarse != "" {
		clientGeoCoarse = &geoCoarse
	}
	if e.RequestID != "" {
		requestID = &e.RequestID
	}
	if coarseIP != "" {
		ipAddress = &coarseIP
	}

	var metadataJSON []byte
	if metadata != nil {
		var err error
		metadataJSON, err = json.Marshal(metadata)
		if err != nil {
			return fmt.Errorf("chain: marshal metadata: %w", err)
		}
	}

	// We need the sequence_no in the hash, which means we have to know
	// it BEFORE the row is committed. Compute it from the head we just
	// read under the per-tenant advisory lock: next = head_seq + 1
	// (or 1 when this is the tenant's first row). The read+insert
	// share this tx, so a later ROLLBACK reverts the allocation
	// cleanly — no sequence-number leaks, no false-positive Gap
	// reports from Verify.
	sequenceNo := headSeq + 1

	// Build the chainRow. UUID values render as canonical hyphenated
	// strings; missing optional fields stay zero-valued and drop out
	// via the omitempty tag.
	cr := chainRow{
		SchemaVersion:   SchemaVersion,
		EventType:       e.EventType,
		EventTimestamp:  eventTimestamp.UTC().Format(time.RFC3339Nano),
		Outcome:         e.Outcome,
		ReasonCode:      e.ReasonCode,
		ActorType:       string(actorType),
		ActorID:         uuidPtrString(e.ActorID),
		ActorSessionID:  uuidPtrString(e.ActorSessionID),
		TargetType:      e.TargetType,
		TargetID:        e.TargetID,
		TenantID:        tenantID.String(),
		SourceService:   sourceService,
		ClientID:        uuidPtrString(e.ClientID),
		ClientIPCoarse:  coarseIP,
		ClientUAFamily:  e.ClientUAFamily,
		ClientGeoCoarse: geoCoarse,
		RequestID:       e.RequestID,
		CorrelationID:   uuidPtrString(correlationID),
		RetentionBucket: string(retentionBucket),
		Metadata:        metadata,
		SequenceNo:      sequenceNo,
		PrevHash:        hex.EncodeToString(prevHash),
	}
	rowHash, err := computeRowHash(cr)
	if err != nil {
		return err
	}

	// INSERT carries the explicit sequence_no this time (we already
	// reserved it). RETURNING is intentionally minimal — we don't need
	// the row id back here.
	if _, err := tx.Exec(ctx,
		`INSERT INTO audit_logs (
			event_type, schema_version, event_timestamp, outcome, reason_code,
			actor_type, actor_id, actor_session_id,
			target_type, target_id, tenant_id, source_service,
			client_id, client_ip_coarse, client_ua_family, client_geo_coarse,
			request_id, correlation_id, metadata,
			sequence_no, prev_hash, row_hash, retention_bucket
		) VALUES ($1, $2, $3, $4, $5,
		          $6, $7, $8,
		          $9, $10, $11, $12,
		          $13, $14, $15, $16,
		          $17, $18, $19,
		          $20, $21, $22, $23)`,
		e.EventType,
		SchemaVersion,
		eventTimestamp,
		e.Outcome,
		reasonCode,
		actorType,
		e.ActorID,
		e.ActorSessionID,
		e.TargetType,
		e.TargetID,
		tenantID,
		sourceService,
		e.ClientID,
		ipAddress,
		clientUAFamily,
		clientGeoCoarse,
		requestID,
		correlationID,
		metadataJSON,
		sequenceNo,
		nullableBytes(prevHash),
		rowHash,
		string(retentionBucket),
	); err != nil {
		return fmt.Errorf("chain: insert: %w", err)
	}

	return nil
}

func (c *Chain) Head(ctx context.Context, q database.Querier, tenantID uuid.UUID) (anchor.ChainHead, error) {
	if tenantID == uuid.Nil {
		tenantID = SingleTenant
	}
	var head anchor.ChainHead
	if err := q.QueryRow(ctx,
		`SELECT tenant_id, sequence_no, row_hash, recorded_at
		   FROM audit_logs
		  WHERE tenant_id = $1
		  ORDER BY sequence_no DESC
		  LIMIT 1`,
		tenantID,
	).Scan(&head.TenantID, &head.SequenceNo, &head.RowHash, &head.AnchoredAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return anchor.ChainHead{TenantID: tenantID}, nil
		}
		return anchor.ChainHead{}, fmt.Errorf("chain: head: %w", err)
	}
	return head, nil
}

func uuidPtrString(u *uuid.UUID) string {
	if u == nil {
		return ""
	}
	return u.String()
}

func nullableBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}
