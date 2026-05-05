//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	auditapi "github.com/abdo75/Schlass/internal/audit"
)

func TestAuditViewerEndpoints(t *testing.T) {
	// This integration package boots Postgres + Valkey through TestMain.
	// If Docker is unavailable, TestMain fails before individual tests can
	// call t.Skip; run this with an available Docker daemon.
	env := NewTestEnv(t)
	adminID := env.SeedAdmin(t, "admin-audit@example.com", "CorrectHorse42!")
	cookie := env.LoginAsAdmin(t, "admin-audit@example.com", "CorrectHorse42!")

	insertAuditViewerRow(t, env, "login.succeeded", &adminID, "admin-audit@example.com", nil, nil, "success")
	insertAuditViewerRow(t, env, "client.created", &adminID, "admin-audit@example.com", ptr("client"), ptr(uuid.NewString()), "success")
	insertAuditViewerRow(t, env, "user.created", &adminID, "admin-audit@example.com", ptr("user"), ptr(uuid.NewString()), "success")

	list := auditViewerGetList(t, env, cookie, "/api/audit")
	if len(list.Items) == 0 {
		t.Fatal("list returned no rows")
	}

	clientOnly := auditViewerGetList(t, env, cookie, "/api/audit?view=client")
	if len(clientOnly.Items) == 0 {
		t.Fatal("client view returned no rows")
	}
	// REQ-AUD-041 (M6): caller's own `audit.viewed` rows pass through any
	// filter — assert event_type matches the filter OR is the caller's own
	// audit.viewed self-record.
	for _, item := range clientOnly.Items {
		if strings.HasPrefix(item.EventType, "client.") {
			continue
		}
		if item.EventType == "audit.viewed" && item.ActorID != nil && *item.ActorID == adminID.String() {
			continue
		}
		t.Fatalf("view=client returned non-client event %q (actor=%v)", item.EventType, item.ActorID)
	}

	_ = auditViewerGetList(t, env, cookie, "/api/audit")
	var viewedCount int
	if err := env.Pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM audit_logs WHERE event_type = 'audit.viewed'`).Scan(&viewedCount); err != nil {
		t.Fatalf("count audit.viewed: %v", err)
	}
	if viewedCount != 1 {
		t.Fatalf("audit.viewed rows = %d, want 1", viewedCount)
	}

	if _, err := env.Pool.Exec(context.Background(), `UPDATE instance_config SET value = '1'::jsonb WHERE key = 'audit_export_max_rows'`); err != nil {
		t.Fatalf("set export cap: %v", err)
	}
	if err := env.SessionStore.MarkMFAVerified(t.Context(), cookie.Value); err != nil {
		t.Fatalf("MarkMFAVerified: %v", err)
	}
	rec := auditViewerPostExport(t, env, cookie, "csv")
	if rec.Code != http.StatusOK {
		t.Fatalf("csv export status = %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Audit-Truncated"); got != "true" {
		t.Fatalf("X-Audit-Truncated = %q, want true", got)
	}
	if err := env.SessionStore.MarkMFAVerified(t.Context(), cookie.Value); err != nil {
		t.Fatalf("MarkMFAVerified: %v", err)
	}
	rec = auditViewerPostExport(t, env, cookie, "jsonl")
	if rec.Code != http.StatusOK {
		t.Fatalf("jsonl export status = %d: %s", rec.Code, rec.Body.String())
	}
	var exportedCount int
	if err := env.Pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM audit_logs WHERE event_type = 'audit.exported'`).Scan(&exportedCount); err != nil {
		t.Fatalf("count audit.exported: %v", err)
	}
	if exportedCount != 2 {
		t.Fatalf("audit.exported rows = %d, want 2", exportedCount)
	}

	// Post-M2 (REQ-AUD-011/030): pseudonymized rows have actor_id=NULL
	// and metadata.pseudonymized_at set. The viewer renders the literal
	// 'pseudonymized' as actor_display, and the row drops out of any
	// actor=email filter (no actor_id to join on).
	//
	// Post-M6 (REQ-AUD-041): the caller's own `audit.viewed` rows are
	// force-included by the audit-the-auditor escape even when the filter
	// would exclude them — so we assert specifically that no row with
	// actor_id == formerID survives the email filter, rather than 0 rows
	// total.
	formerID := env.DirectCreateUser(t, "former@example.com", "user")
	insertAuditViewerRow(t, env, "login.succeeded", &formerID, "", nil, nil, "success")
	pseudo := auditViewerGetList(t, env, cookie, "/api/audit?actor=former@example.com")
	for _, item := range pseudo.Items {
		if item.ActorID != nil && *item.ActorID == formerID.String() {
			t.Fatalf("pseudonymized actor must not match old email, got row with actor_id=%s", *item.ActorID)
		}
	}
	all := auditViewerGetList(t, env, cookie, "/api/audit")
	foundPseudo := false
	for _, item := range all.Items {
		if item.ActorID == nil && item.ActorPseudonymized && item.ActorDisplay == "pseudonymized" {
			foundPseudo = true
		}
	}
	if !foundPseudo {
		t.Fatal("pseudonymized row did not render as 'pseudonymized'")
	}
}

func auditViewerRequest(t *testing.T, env *TestEnv, cookie *http.Cookie, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, path, nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	return rec
}

func auditViewerPostExport(t *testing.T, env *TestEnv, cookie *http.Cookie, format string) *httptest.ResponseRecorder {
	t.Helper()
	body := bytes.NewBufferString(`{"since":"24h","view":"all","format":"` + format + `"}`)
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/audit/export", body)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	return rec
}

func auditViewerGetList(t *testing.T, env *TestEnv, cookie *http.Cookie, path string) auditapi.ListResponse {
	t.Helper()
	rec := auditViewerRequest(t, env, cookie, "GET", path)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s returned %d: %s", path, rec.Code, rec.Body.String())
	}
	var out auditapi.ListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	return out
}

// Post-M2 (REQ-AUD-011): actor_email column is gone. The viewer
// derives the actor display via a live join on users; pseudonymized
// rows have actor_id NULL + metadata.pseudonymized_at set. Test rows
// emulate that shape — the actorEmail parameter is preserved for
// callers but only used to flip the row into the pseudonymized state
// when empty (mirrors the pre-M2 "actor_email NULL" convention).
func insertAuditViewerRow(t *testing.T, env *TestEnv, eventType string, actorID *uuid.UUID, actorEmail string, targetType, targetID *string, outcome string) {
	t.Helper()
	var actor any
	if actorID != nil {
		actor = *actorID
	}
	metadata := `{}`
	// Pre-M2 callers used empty actorEmail to mean "this row is for a
	// pseudonymized actor". Post-M2 we model that as actor_id=NULL +
	// metadata.pseudonymized_at populated.
	if actorID != nil && actorEmail == "" {
		actor = nil
		metadata = `{"pseudonymized_at": "2026-04-30T00:00:00Z"}`
	}
	// Post-M3 (000005 + 000006): sequence_no is NOT NULL with no DEFAULT;
	// raw INSERTs that bypass chain.Append must supply it explicitly.
	if _, err := env.Pool.Exec(context.Background(), `
		INSERT INTO audit_logs (event_type, actor_id, target_type, target_id, outcome, metadata, sequence_no)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb,
		        (SELECT COALESCE(MAX(sequence_no), 0) + 1 FROM audit_logs))
	`, eventType, actor, targetType, targetID, outcome, metadata); err != nil {
		t.Fatalf("insert audit row %s: %v", eventType, err)
	}
}

func ptr(s string) *string {
	return &s
}
