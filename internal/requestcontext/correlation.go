// Package requestcontext holds context-key helpers for per-request metadata
// (currently just the correlation ID) that need to be read by BOTH the
// middleware package and the store package. A dedicated leaf package prevents
// the middleware→store import the rest of the codebase relies on from
// becoming a cycle.
package requestcontext

import "context"

// contextKey is unexported so callers outside this package cannot forge or
// read the value except through the exported helpers.
type contextKey string

const correlationIDKey contextKey = "correlation_id"

// WithCorrelationID returns a new context carrying the given correlation id.
// Called by middleware.RequestLogging on every inbound HTTP request.
func WithCorrelationID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, correlationIDKey, id)
}

// CorrelationID returns the correlation id attached to the context by
// WithCorrelationID, or the empty string if none is present (e.g., a
// background job, a test that fabricates a context, or production code that
// somehow bypasses RequestLogging).
func CorrelationID(ctx context.Context) string {
	if v, ok := ctx.Value(correlationIDKey).(string); ok {
		return v
	}
	return ""
}
