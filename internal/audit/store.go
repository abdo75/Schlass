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
//
// REQ-AUD-011/030/031 (M2): PII closure. actor_email is gone from the
// schema; the IPAddress field is coarsened at emit time per the Store's
// IPMode setting (/24 v4, /48 v6, country-only, or off) and written to
// client_ip_coarse. The viewer derives actor display by joining users
// at read time. UA strings are parsed to family/major before storage —
// the raw header is never persisted.
package audit

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/abdo75/Schlass/internal/database"
)

// SchemaVersion is the current row schema. Bumped on breaking field
// changes per REQ-AUD-010.
const SchemaVersion = 1

// SingleTenant is the deployment-wide tenant_id constant. Multi-tenant
// deployments override per-row at emit time once tenancy is wired.
var SingleTenant = uuid.Nil

// IPMode controls how the IPAddress field on Event is transformed
// before being written to client_ip_coarse. Set once at startup from
// instance_config["audit.client_ip_mode"].
type IPMode string

const (
	// IPModeCoarse zeroes host bits below /24 (v4) or /48 (v6).
	// Default per REQ-AUD-031.
	IPModeCoarse IPMode = "coarse"
	// IPModeCountry stores NULL in client_ip_coarse and writes a
	// country code into client_geo_coarse via a country-lookup
	// provider. M2 ships without a provider wired; in that case we
	// store the literal "country_lookup_unconfigured" sentinel so
	// operators can spot the misconfiguration in the viewer.
	IPModeCountry IPMode = "country"
	// IPModeOff drops the IP entirely. client_ip_coarse and
	// client_geo_coarse both write NULL.
	IPModeOff IPMode = "off"
)

// ParseIPMode validates an instance_config value and returns the
// corresponding IPMode. Unknown values fail rather than silently
// fall back so a typo in the config doesn't quietly disable coarsening.
func ParseIPMode(s string) (IPMode, error) {
	switch IPMode(s) {
	case IPModeCoarse, IPModeCountry, IPModeOff:
		return IPMode(s), nil
	default:
		return "", fmt.Errorf("audit: unknown ip mode %q (want coarse|country|off)", s)
	}
}

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
//
// ActorEmail is a transition-only field. The schema column was dropped
// in M2 (REQ-AUD-011); the value is no longer written. Call sites still
// pass it because removing every emit-site signature in one milestone
// would dwarf the actual PII closure work — M7 is the natural cleanup.
type Event struct {
	EventType       string
	EventTimestamp  time.Time
	Outcome         string
	ReasonCode      string
	ActorType       ActorType
	ActorID         *uuid.UUID
	ActorEmail      string // accepted but not persisted post-M2; see type doc
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

// Store writes audit rows into the audit_logs table.
type Store struct {
	ipMode IPMode
}

// NewStore returns a Store using IPModeCoarse by default. Boot paths
// that read instance_config use NewStoreWithIPMode to override.
func NewStore() *Store {
	return &Store{ipMode: IPModeCoarse}
}

// NewStoreWithIPMode returns a Store whose Emit applies the given IP
// coarsening mode to the IPAddress field on every event. Empty string
// is treated as IPModeCoarse so the caller doesn't have to duplicate
// the default.
func NewStoreWithIPMode(mode IPMode) *Store {
	if mode == "" {
		mode = IPModeCoarse
	}
	return &Store{ipMode: mode}
}

// IPMode returns the configured coarsening mode. Exposed for tests and
// for the boot path's startup log.
func (s *Store) IPMode() IPMode { return s.ipMode }

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

// coarsenIP applies REQ-AUD-031 prefix masking. Returns the masked
// network as the prefix (e.g. "192.168.5.0/24") so the inet column
// stores the prefix address with a /32 host that already has the host
// bits zeroed. Empty input or unparseable input yields an empty string;
// caller writes NULL to the column in that case.
//
// IPv4-mapped IPv6 ("::ffff:192.168.5.42") is unmapped first so a v4
// address arriving via a dual-stack listener gets the /24 v4 mask, not a
// /48 over the full 128 bits (which would zero the v4 octets entirely).
func coarsenIP(raw string) string {
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return ""
	}
	addr = addr.Unmap()
	bits := 24
	if addr.Is6() {
		bits = 48
	}
	prefix, err := addr.Prefix(bits)
	if err != nil {
		return ""
	}
	return prefix.Masked().Addr().String()
}

// applyIPMode transforms the per-event IPAddress + ClientGeoCoarse
// according to the Store's mode. Returns the column values to write.
func (s *Store) applyIPMode(rawIP, geo string) (ipColumn, geoColumn string) {
	switch s.ipMode {
	case IPModeOff:
		return "", ""
	case IPModeCountry:
		// Country provider not wired in M2; leave geo as the caller
		// supplied (likely empty) and write a sentinel so operators
		// see the misconfiguration in the viewer instead of a silent
		// blank cell.
		if geo == "" {
			geo = "country_lookup_unconfigured"
		}
		return "", geo
	case IPModeCoarse, "":
		fallthrough
	default:
		if rawIP == "" {
			return "", geo
		}
		coarse := coarsenIP(rawIP)
		return coarse, geo
	}
}

// Emit writes one audit row inside an existing transaction. The pgx.Tx
// signature is type-level enforcement of REQ-AUD-062: pool/non-tx
// callers cannot compile against this. Unknown event_types fail closed
// via Lookup + ErrUnknownEventType.
//
// Post-M3 (REQ-AUD-012/020/021/023): Emit delegates to Chain.Append,
// which serialises per-tenant inserts via pg_advisory_xact_lock,
// computes the canonical-JSON sha256 row_hash, and INSERTs with a
// non-null prev_hash that links to the previous row. There is no
// non-chained path — every emit is part of the chain.
func (s *Store) Emit(ctx context.Context, tx pgx.Tx, e Event) error {
	if _, ok := Lookup(e.EventType); !ok {
		return fmt.Errorf("%w: %q", ErrUnknownEventType, e.EventType)
	}
	return (&Chain{}).Append(ctx, tx, s, e)
}

// PseudonymizeUser dispatches to the audit_log_pseudonymize_user
// SECURITY DEFINER function — the single sanctioned mutation on
// audit_logs. schlass_app has no direct UPDATE on the table, only
// EXECUTE on this function. GDPR Art. 17(3)(b) compliance path.
//
// Post-M2: the function nulls actor_id and writes
// metadata.pseudonymized_at instead of overwriting actor_email (which
// no longer exists). Returned count is the rows touched on this call;
// rows already pseudonymized are skipped via the metadata marker.
func (s *Store) PseudonymizeUser(ctx context.Context, q database.Querier, userID uuid.UUID) (int, error) {
	var rows int
	if err := q.QueryRow(ctx, `SELECT audit_log_pseudonymize_user($1)`, userID).Scan(&rows); err != nil {
		return 0, fmt.Errorf("audit pseudonymize: %w", err)
	}
	return rows, nil
}
