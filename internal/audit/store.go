// Append-only audit-log store. Rows are insert-only at the DB level
// (RLS + no UPDATE/DELETE for schlass_app). PseudonymizeUser dispatches
// the single sanctioned mutation via a SECURITY DEFINER function.
//
// REQ-AUD-008/010/062 (M1): every row carries the spec column delta
// (schema_version, recorded_at, event_timestamp, reason_code,
// actor_type, actor_session_id, tenant_id, source_service, client_*,
// request_id, correlation_id) and references an event_type registered
// in registry.go. Emit takes pgx.Tx at the type level so pool/non-tx
// callers cannot compile against this signature — partial commits
// where the audit row is missing the originating mutation, or vice
// versa, are unrepresentable.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/abdo75/Schlass/internal/database"
	"github.com/abdo75/Schlass/internal/middleware"
)

// SchemaVersion is the current row schema. Bumped on breaking field
// changes per REQ-AUD-010.
const SchemaVersion = 1

// SingleTenant is the deployment-wide tenant_id constant. Multi-tenant
// deployments override per-row at emit time once tenancy is wired.
var SingleTenant = uuid.Nil

// ActorType enumerates REQ-AUD-010 actor_type values.
type ActorType string

const (
	ActorTypeUser      ActorType = "user"
	ActorTypeService   ActorType = "service"
	ActorTypeSystem    ActorType = "system"
	ActorTypeAnonymous ActorType = "anonymous"
)

// Event is the typed payload for one audit row. Mirrors REQ-AUD-010.
// Optional fields default at Emit time: EventTimestamp=now, ActorType
// from ActorID presence, TenantID=SingleTenant, SourceService from
// event_type prefix, CorrelationID from middleware.CorrelationID(ctx).
type Event struct {
	EventType       string
	EventTimestamp  time.Time
	Outcome         string
	ReasonCode      string
	ActorType       ActorType
	ActorID         *uuid.UUID
	ActorEmail      string // M2 will drop this column; field stays for transition
	ActorSessionID  *uuid.UUID
	TargetType      string
	TargetID        string
	TenantID        uuid.UUID
	SourceService   string
	ClientID        *uuid.UUID
	IPAddress       string
	ClientUAFamily  string
	ClientGeoCoarse string
	RequestID       string
	CorrelationID   *uuid.UUID
	Metadata        map[string]any
}

// EventBuilder gives ergonomic site code without forgetting required
// fields. Callers compose with chained With* setters and finish via
// Build, or pass the struct literal directly to Emit.
type EventBuilder struct{ e Event }

func NewEvent(eventType string) *EventBuilder {
	return &EventBuilder{e: Event{EventType: eventType}}
}

func (b *EventBuilder) WithOutcome(outcome string) *EventBuilder {
	b.e.Outcome = outcome
	return b
}

// WithActor sets ActorID + ActorEmail and defaults ActorType from
// ActorID presence (user when non-nil, system otherwise). Callers that
// need a specific ActorType (service, anonymous) set it directly on the
// returned builder via the e field, or pass an Event literal to Emit.
func (b *EventBuilder) WithActor(id *uuid.UUID, email string) *EventBuilder {
	b.e.ActorID = id
	b.e.ActorEmail = email
	if id != nil {
		b.e.ActorType = ActorTypeUser
	} else {
		b.e.ActorType = ActorTypeSystem
	}
	return b
}

func (b *EventBuilder) WithActorSession(sessionID *uuid.UUID) *EventBuilder {
	b.e.ActorSessionID = sessionID
	return b
}

func (b *EventBuilder) WithTarget(targetType, targetID string) *EventBuilder {
	b.e.TargetType = targetType
	b.e.TargetID = targetID
	return b
}

func (b *EventBuilder) WithClient(clientID *uuid.UUID) *EventBuilder {
	b.e.ClientID = clientID
	return b
}

func (b *EventBuilder) WithIP(ip string) *EventBuilder {
	b.e.IPAddress = ip
	return b
}

func (b *EventBuilder) WithReason(code string) *EventBuilder {
	b.e.ReasonCode = code
	return b
}

func (b *EventBuilder) WithMetadata(meta map[string]any) *EventBuilder {
	b.e.Metadata = meta
	return b
}

func (b *EventBuilder) Build() Event {
	return b.e
}

type Store struct{}

func NewStore() *Store {
	return &Store{}
}

// sourceServiceFromEventType returns the originating component for an
// event_type, mirroring the M1 migration's CASE backfill so historical
// and live rows agree on the bucket.
func sourceServiceFromEventType(eventType string) string {
	switch {
	case startsWith(eventType, "oidc."):
		return "authserver"
	case startsWith(eventType, "login."),
		startsWith(eventType, "logout."),
		startsWith(eventType, "auth."),
		startsWith(eventType, "mfa."),
		startsWith(eventType, "password."),
		startsWith(eventType, "password_reset."),
		startsWith(eventType, "session."),
		startsWith(eventType, "account."):
		return "auth"
	case startsWith(eventType, "user."):
		return "users"
	case startsWith(eventType, "client."):
		return "clients"
	case startsWith(eventType, "config."):
		return "instanceconfig"
	case startsWith(eventType, "audit."):
		return "audit"
	case startsWith(eventType, "setup."):
		return "server"
	default:
		return "unknown"
	}
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// Emit writes one audit row inside an existing transaction. The pgx.Tx
// signature is type-level enforcement of REQ-AUD-062: pool/non-tx
// callers cannot compile against this. Unknown event_types fail closed
// via Lookup + ErrUnknownEventType.
func (s *Store) Emit(ctx context.Context, tx pgx.Tx, e Event) error {
	if _, ok := Lookup(e.EventType); !ok {
		return fmt.Errorf("%w: %q", ErrUnknownEventType, e.EventType)
	}

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

	sourceService := e.SourceService
	if sourceService == "" {
		sourceService = sourceServiceFromEventType(e.EventType)
	}

	// correlation_id: prefer the explicit field on Event, else fall back
	// to the middleware-injected request correlation ID. Mirror into
	// metadata under the same key so the viewer's existing event-grouping
	// (UI reads metadata.correlation_id) keeps working until M7 surfaces
	// the column directly. Mirror whichever source actually populated the
	// column so explicit-field callers (CLI/sweeper paths without a
	// request middleware) don't end up with a column-only row that the
	// viewer can't group.
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

	var metadataJSON []byte
	if metadata != nil {
		var err error
		metadataJSON, err = json.Marshal(metadata)
		if err != nil {
			return fmt.Errorf("audit emit: marshal metadata: %w", err)
		}
	}

	// ip_address is INET + nullable — pass nil when empty; pgx would
	// otherwise cast "" to inet and Postgres rejects with 22P02.
	var ipAddress *string
	if e.IPAddress != "" {
		ipAddress = &e.IPAddress
	}

	// actor_email empty string would defeat the COALESCE(actor_email, …, 'System')
	// fallback in list_select.go — store NULL so system-actor rows render as 'System'.
	var actorEmail *string
	if e.ActorEmail != "" {
		actorEmail = &e.ActorEmail
	}

	var reasonCode *string
	if e.ReasonCode != "" {
		reasonCode = &e.ReasonCode
	}

	var clientUAFamily *string
	if e.ClientUAFamily != "" {
		clientUAFamily = &e.ClientUAFamily
	}

	var clientGeoCoarse *string
	if e.ClientGeoCoarse != "" {
		clientGeoCoarse = &e.ClientGeoCoarse
	}

	var requestID *string
	if e.RequestID != "" {
		requestID = &e.RequestID
	}

	// event_timestamp: zero value falls back to the DB DEFAULT now().
	// Pass nil so the column default fires; otherwise the explicit value
	// wins so tests / replay paths can backdate rows.
	var eventTimestamp *time.Time
	if !e.EventTimestamp.IsZero() {
		t := e.EventTimestamp
		eventTimestamp = &t
	}

	_, err := tx.Exec(ctx,
		`INSERT INTO audit_logs (
			event_type, schema_version, event_timestamp, outcome, reason_code,
			actor_type, actor_id, actor_email, actor_session_id,
			target_type, target_id, tenant_id, source_service,
			client_id, ip_address, client_ua_family, client_geo_coarse,
			request_id, correlation_id, metadata
		)
		VALUES ($1, $2, COALESCE($3, now()), $4, $5,
		        $6, $7, $8, $9,
		        $10, $11, $12, $13,
		        $14, $15, $16, $17,
		        $18, $19, $20)`,
		e.EventType,
		SchemaVersion,
		eventTimestamp,
		e.Outcome,
		reasonCode,
		actorType,
		e.ActorID,
		actorEmail,
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
	)
	if err != nil {
		return fmt.Errorf("audit emit: %w", err)
	}
	return nil
}

// PseudonymizeUser dispatches to the audit_log_pseudonymize_user
// SECURITY DEFINER function — the single sanctioned mutation on
// audit_logs. schlass_app has no direct UPDATE on the table, only
// EXECUTE on this function. GDPR Art. 17(3)(b) compliance path.
func (s *Store) PseudonymizeUser(ctx context.Context, q database.Querier, userID uuid.UUID) (int, error) {
	var rows int
	if err := q.QueryRow(ctx, `SELECT audit_log_pseudonymize_user($1)`, userID).Scan(&rows); err != nil {
		return 0, fmt.Errorf("audit pseudonymize: %w", err)
	}
	return rows, nil
}
