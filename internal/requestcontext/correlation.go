// Package requestcontext holds context-key helpers read by both middleware
// and store. Dedicated leaf package prevents middleware→store from becoming
// a cycle.
package requestcontext

import "context"

type contextKey string

const correlationIDKey contextKey = "correlation_id"

func WithCorrelationID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, correlationIDKey, id)
}

func CorrelationID(ctx context.Context) string {
	if v, ok := ctx.Value(correlationIDKey).(string); ok {
		return v
	}
	return ""
}
