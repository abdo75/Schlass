// CAEPStreamer wraps an inner Streamer and, when the stream format is
// "caep", projects each event to an RFC 8417 SET before pushing. Events
// with no registered CAEP URN mapping are silently dropped. The inner
// streamer receives a synthetic single-event batch containing a pre-built
// SETEvent whose EventType carries the signed JWS string; both syslog and
// OTLP backends treat the EventType field as the log body when it is a
// well-formed JWS.
package stream

import (
	"context"
	"log/slog"
)

// SETProjector is implemented by audit.ProjectCAEP and audit.SignCAEP.
// Declared here as a function type to keep this package free of an import
// cycle through the audit package.
type SETProjector func(evt Event) (jws string, ok bool, err error)

// CAEPStreamer delegates to an inner Streamer but projects every Event
// to a signed RFC 8417 SET before pushing. Non-mapped events are dropped.
type CAEPStreamer struct {
	inner    Streamer
	projSign SETProjector
}

// NewCAEPStreamer wraps inner with the given project+sign function.
func NewCAEPStreamer(inner Streamer, projSign SETProjector) *CAEPStreamer {
	return &CAEPStreamer{inner: inner, projSign: projSign}
}

// Push projects each event in the batch. Mapped events are signed and
// forwarded as a SETEvent batch; unmapped events are skipped. If the
// entire batch has no mapped events, Push is a no-op (does not call
// inner.Push), which avoids waking syslog/OTLP for batches that are
// entirely non-CAEP.
func (c *CAEPStreamer) Push(ctx context.Context, batch []Event) error {
	var setEvents []Event
	for _, evt := range batch {
		jws, ok, err := c.projSign(evt)
		if err != nil {
			slog.Warn("audit stream caep: projection error, skipping event",
				"event_type", evt.EventType, "error", err)
			continue
		}
		if !ok {
			slog.Debug("audit stream caep: no mapping, skipping", "event_type", evt.EventType)
			continue
		}
		// Carry the JWS in a cloned Event. Both syslog (MSG body) and OTLP
		// (log record body) will use EventType as the payload when it is a
		// JWS string; we repurpose the field to avoid introducing a new
		// protocol type. The original event_id and tenant info are preserved
		// so the inner backend can still do deduplication.
		//
		// Choice: embed JWS in EventType rather than a new field to keep the
		// stream.Event shape stable and avoid a protocol-version bump.
		cloned := evt
		cloned.EventType = jws
		setEvents = append(setEvents, cloned)
	}
	if len(setEvents) == 0 {
		return nil
	}
	return c.inner.Push(ctx, setEvents)
}

// Close forwards to the inner Streamer.
func (c *CAEPStreamer) Close() error {
	return c.inner.Close()
}

// Compile-time assertion.
var _ Streamer = (*CAEPStreamer)(nil)
