//go:build integration

package integration

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/abdo75/Schlass/internal/audit"
)

// TestAuditSchemaBaseline_ColumnsExist asserts every spec-mandated column
// from REQ-AUD-010 (added by migration 000003) is present with the
// expected SQL type. Catches accidental drops of any single column in
// future migrations.
func TestAuditSchemaBaseline_ColumnsExist(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	want := map[string]string{
		"schema_version":    "integer",
		"recorded_at":       "timestamp with time zone",
		"event_timestamp":   "timestamp with time zone",
		"reason_code":       "text",
		"actor_type":        "text",
		"actor_session_id":  "uuid",
		"tenant_id":         "uuid",
		"source_service":    "text",
		"client_ua_family":  "text",
		"client_geo_coarse": "text",
		"request_id":        "text",
		"correlation_id":    "uuid",
		"sequence_no":       "bigint",
		"prev_hash":         "bytea",
		"row_hash":          "bytea",
	}

	for column, wantType := range want {
		var dataType string
		err := env.Pool.QueryRow(context.Background(), `
			SELECT data_type FROM information_schema.columns
			WHERE table_schema = 'public'
			  AND table_name = 'audit_logs'
			  AND column_name = $1
		`, column).Scan(&dataType)
		if err != nil {
			t.Errorf("column %s: lookup failed: %v", column, err)
			continue
		}
		if dataType != wantType {
			t.Errorf("column %s: data_type = %q, want %q", column, dataType, wantType)
		}
	}
}

// TestAuditSchemaBaseline_OutcomeAcceptsDenied verifies the M1 widened
// outcome CHECK admits 'denied'. Round-trip through Emit because that's
// the only sanctioned write path post-M1.
func TestAuditSchemaBaseline_OutcomeAcceptsDenied(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	store := audit.NewStore()
	tx, err := env.Pool.Begin(context.Background())
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	if err := store.Emit(context.Background(), tx, audit.Event{
		EventType:  "auth.permission_denied",
		Outcome:    "denied",
		TargetType: "permission",
		TargetID:   "users.create",
		Metadata:   map[string]any{"method": "POST", "path": "/api/users"},
	}); err != nil {
		t.Fatalf("emit denied row: %v", err)
	}

	var n int
	if err := tx.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_logs WHERE outcome = 'denied'`).Scan(&n); err != nil {
		t.Fatalf("count denied rows: %v", err)
	}
	if n != 1 {
		t.Fatalf("want 1 denied row in tx, got %d", n)
	}

	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// TestAuditSchemaBaseline_UnknownEventTypeFailsClosed asserts Emit
// rejects unregistered event_types via ErrUnknownEventType and writes
// no row. Registry is the single source of truth for known events
// (REQ-AUD-008); fail-closed is non-negotiable because retention +
// streaming behaviour is undefined for unregistered types.
func TestAuditSchemaBaseline_UnknownEventTypeFailsClosed(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	store := audit.NewStore()
	tx, err := env.Pool.Begin(context.Background())
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	err = store.Emit(context.Background(), tx, audit.Event{
		EventType:  "made.up.event",
		Outcome:    "success",
		TargetType: "user",
	})
	if err == nil {
		t.Fatal("emit unknown event_type: want error, got nil")
	}
	if !errors.Is(err, audit.ErrUnknownEventType) {
		t.Fatalf("emit unknown event_type: want ErrUnknownEventType, got %v", err)
	}
	if !strings.Contains(err.Error(), "made.up.event") {
		t.Fatalf("emit unknown event_type: error %q should mention the offending event_type", err.Error())
	}

	var n int
	if err := tx.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_logs WHERE event_type = 'made.up.event'`).Scan(&n); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 rows for rejected event_type, got %d", n)
	}
}

// TestAuditSchemaBaseline_EmitPopulatesAllSpecColumns commits one row
// via Emit and asserts every spec column is populated as expected:
// schema_version=1, source_service derived from prefix, actor_type
// inferred from ActorID presence, tenant_id=SingleTenant, correlation_id
// from middleware ctx, ip_address from the IPAddress field.
func TestAuditSchemaBaseline_EmitPopulatesAllSpecColumns(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	actorID := uuid.New()
	correlationID := uuid.New()
	clientID := uuid.New()
	sessionID := uuid.New()

	store := audit.NewStore()
	tx, err := env.Pool.Begin(context.Background())
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	if err := store.Emit(context.Background(), tx, audit.Event{
		EventType:      "login.succeeded",
		Outcome:        "success",
		ActorID:        &actorID,
		ActorEmail:     "alice@example.com",
		ActorSessionID: &sessionID,
		TargetType:     "user",
		TargetID:       actorID.String(),
		ClientID:       &clientID,
		IPAddress:      "203.0.113.7",
		ClientUAFamily: "Firefox",
		RequestID:      "req-abc",
		CorrelationID:  &correlationID,
		ReasonCode:     "ok",
		Metadata:       map[string]any{"method": "password"},
	}); err != nil {
		t.Fatalf("emit: %v", err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit: %v", err)
	}

	var (
		schemaVersion int
		sourceService string
		actorType     string
		tenantID      uuid.UUID
		ipAddress     string
		gotCorrID     uuid.UUID
		reasonCode    string
		uaFamily      string
		requestID     string
		gotSessionID  uuid.UUID
	)
	err = env.Pool.QueryRow(context.Background(),
		`SELECT schema_version, source_service, actor_type, tenant_id,
		        host(ip_address), correlation_id, reason_code,
		        client_ua_family, request_id, actor_session_id
		   FROM audit_logs
		  WHERE event_type = 'login.succeeded'
		    AND actor_id = $1`, actorID).Scan(
		&schemaVersion, &sourceService, &actorType, &tenantID,
		&ipAddress, &gotCorrID, &reasonCode, &uaFamily, &requestID, &gotSessionID,
	)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}

	if schemaVersion != audit.SchemaVersion {
		t.Errorf("schema_version = %d, want %d", schemaVersion, audit.SchemaVersion)
	}
	if sourceService != "auth" {
		t.Errorf("source_service = %q, want %q (derived from login.* prefix)", sourceService, "auth")
	}
	if actorType != string(audit.ActorTypeUser) {
		t.Errorf("actor_type = %q, want %q (inferred from ActorID presence)", actorType, audit.ActorTypeUser)
	}
	if tenantID != audit.SingleTenant {
		t.Errorf("tenant_id = %s, want SingleTenant %s", tenantID, audit.SingleTenant)
	}
	if ipAddress != "203.0.113.7" {
		t.Errorf("ip_address = %q, want %q", ipAddress, "203.0.113.7")
	}
	if gotCorrID != correlationID {
		t.Errorf("correlation_id = %s, want %s", gotCorrID, correlationID)
	}
	if reasonCode != "ok" {
		t.Errorf("reason_code = %q, want %q", reasonCode, "ok")
	}
	if uaFamily != "Firefox" {
		t.Errorf("client_ua_family = %q, want %q", uaFamily, "Firefox")
	}
	if requestID != "req-abc" {
		t.Errorf("request_id = %q, want %q", requestID, "req-abc")
	}
	if gotSessionID != sessionID {
		t.Errorf("actor_session_id = %s, want %s", gotSessionID, sessionID)
	}
}
