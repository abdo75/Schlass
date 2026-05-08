// CAEPStreamer wraps an inner Streamer and projects each event to a signed
// RFC 8417 SET (JWS) before pushing. Events with no CAEP URN mapping are
// silently dropped. The signed JWS is placed in Event.RawSET; backends
// emit it as the message body verbatim so the self-describing SET reaches
// the receiver intact without requiring extra structured-data fields.
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
// The signed JWS is stored in Event.RawSET so backends emit it verbatim
// as the message body without corrupting EventType or other fields.
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
		// Carry the JWS in RawSET. Both syslog and OTLP backends write
		// RawSET verbatim as the message body when it is non-empty, and
		// omit the per-event structured fields (those are already encoded
		// inside the self-describing SET). EventType is left intact so the
		// event is still identifiable for logging/metrics.
		cloned := evt
		cloned.RawSET = jws
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
