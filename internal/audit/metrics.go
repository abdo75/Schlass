// Prometheus metric registration for the audit subsystem (REQ-AUD-061
// observability + plan §M8 step 9). Counters live as package globals so
// every emit/stream code path can increment the same instance, and
// `/metrics` returns them via promhttp.Handler() wired in router.go.
package audit

import (
	"context"
	"errors"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// auditWriteFailures counts primary in-tx audit-row write failures
// (Chain.Append → INSERT error) by event_type. A non-zero rate on an
// IsCritical=true event_type is REQ-AUD-060-actionable.
var auditWriteFailures = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "audit_write_failures_total",
		Help: "Total primary in-tx audit-row write failures, by event_type.",
	},
	[]string{"event_type"},
)

// auditStreamFailures counts outbound streamer push failures by backend.
var auditStreamFailures = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "audit_stream_failures_total",
		Help: "Total outbound streamer push failures, by configured backend.",
	},
	[]string{"backend"},
)

// IncWriteFailure bumps audit_write_failures_total{event_type=...}.
// Called from chain.go on Append error.
func IncWriteFailure(eventType string) {
	auditWriteFailures.WithLabelValues(eventType).Inc()
}

// IncStreamFailure bumps audit_stream_failures_total{backend=...}.
// Called from stream_worker on each push error.
func IncStreamFailure(backend string) {
	auditStreamFailures.WithLabelValues(backend).Inc()
}

// RegisterDLQGauge wires audit_stream_dlq_size as a GaugeFunc that
// runs `SELECT count(*) FROM audit_stream_dlq WHERE attempt_count >= 0`
// on each scrape. The query is bounded by the table's primary key
// index — even at thousands of pending rows it returns in milliseconds.
//
// Idempotent: if the gauge is already registered (re-call from tests
// using a shared boot path), the duplicate-registration error is
// logged and swallowed so concurrent test setups don't panic.
func RegisterDLQGauge(pool *pgxpool.Pool) {
	g := prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Name: "audit_stream_dlq_size",
			Help: "Current count of audit_stream_dlq rows still being retried (attempt_count >= 0).",
		},
		func() float64 {
			var n int64
			if err := pool.QueryRow(context.Background(),
				`SELECT count(*) FROM audit_stream_dlq WHERE attempt_count >= 0`,
			).Scan(&n); err != nil {
				return 0
			}
			return float64(n)
		},
	)
	if err := prometheus.Register(g); err != nil {
		// AlreadyRegisteredError is the only expected failure; the
		// existing instance keeps serving correctly.
		var are prometheus.AlreadyRegisteredError
		if !errors.As(err, &are) {
			slog.Warn("audit metrics: register dlq gauge", "error", err)
		}
	}
}
