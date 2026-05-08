// Package stream implements outbound delivery of audit_logs rows to an
// external SIEM (REQ-AUD-050). Two reference backends ship: syslog
// RFC 5424 over TCP+TLS and OTLP HTTP/JSON. Failed pushes are routed to
// audit_stream_dlq for exponential-backoff retry by the watermark
// worker (REQ-AUD-061). The primary in-tx audit write is unaffected by
// streaming success — the row is durable in audit_logs regardless.
//
// The Event type here is the post-DB-read projection of an audit_logs
// row. It is intentionally separated from audit.Event (the pre-emit
// builder shape) so this package can stay free of cyclic dependencies.
package stream

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// Event is a single audit row as it appears to a streamer. All PII
// transformations (IP coarsening, UA family extraction) have already
// been applied at emit time per M2; the streamer treats every string
// field as opaque.
//
// RawSET, when non-empty, carries a signed RFC 8417 JWS string produced
// by CAEPStreamer. Syslog and OTLP backends write this verbatim as the
// message body and suppress the structured-data / attribute fields that
// describe an individual event (those are already encoded in the SET).
type Event struct {
	ID              uuid.UUID
	TenantID        uuid.UUID
	SequenceNo      int64
	EventType       string
	EventTimestamp  time.Time
	Outcome         string
	ReasonCode     *string
	ActorType       string
	ActorID        *uuid.UUID
	ActorSessionID *uuid.UUID
	TargetType     *string
	TargetID       *string
	SourceService   string
	ClientIPCoarse *string
	ClientGeoCoarse *string
	ClientUAFamily *string
	RequestID      *string
	CorrelationID  *uuid.UUID
	RetentionBucket string
	Metadata        map[string]any
	// RawSET carries a signed RFC 8417 JWS when the event was projected
	// through CAEPStreamer. Non-empty means the backends should emit it
	// verbatim as the log body instead of structured fields.
	RawSET string
}

// Streamer is the contract every backend implements. Push delivers a
// batch and returns an error iff the entire batch failed; partial-batch
// failure is not modelled — receivers are required to dedupe by
// `event.id`, so the worker re-pushes the whole batch on retry.
type Streamer interface {
	Push(ctx context.Context, batch []Event) error
	Close() error
}

// PushTimeout caps per-push duration so a hung TCP connection or HTTP
// receiver never blocks the worker indefinitely.
const PushTimeout = 30 * time.Second

// ErrNotConfigured signals the worker that the configured backend is
// "none" — boot proceeds, worker no-ops.
var ErrNotConfigured = errors.New("audit stream: backend not configured")

// backoffSchedule maps DLQ attempt_count → next_retry_at offset.
// attempt_count=1 means the row has been tried once; the next retry
// happens after backoffSchedule[0] etc. Bounded at the last entry.
var backoffSchedule = []time.Duration{
	1 * time.Minute,
	2 * time.Minute,
	5 * time.Minute,
	15 * time.Minute,
	1 * time.Hour,
	6 * time.Hour,
	24 * time.Hour,
}

// Backoff returns the wait time before the next retry given how many
// attempts have already been made (1 = one prior failure).
func Backoff(attemptCount int) time.Duration {
	if attemptCount <= 0 {
		return backoffSchedule[0]
	}
	idx := attemptCount - 1
	if idx >= len(backoffSchedule) {
		idx = len(backoffSchedule) - 1
	}
	return backoffSchedule[idx]
}

// MaxRetainAge is the cumulative time-since-DLQ-insert past which a row
// is permanently dropped (attempt_count = -1) and `audit.stream.dropped`
// is emitted once.
const MaxRetainAge = 24 * time.Hour
