//go:build integration

package integration

import (
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
	for _, item := range clientOnly.Items {
		if !strings.HasPrefix(item.EventType, "client.") {
			t.Fatalf("view=client returned non-client event %q", item.EventType)
		}
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
	rec := auditViewerRequest(t, env, cookie, "GET", "/api/audit/export?format=csv")
	if rec.Code != http.StatusOK {
		t.Fatalf("csv export status = %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Audit-Truncated"); got != "true" {
		t.Fatalf("X-Audit-Truncated = %q, want true", got)
	}
	rec = auditViewerRequest(t, env, cookie, "GET", "/api/audit/export?format=jsonl")
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

	formerID := env.DirectCreateUser(t, "former@example.com", "user")
	insertAuditViewerRow(t, env, "login.succeeded", &formerID, "", nil, nil, "success")
	pseudo := auditViewerGetList(t, env, cookie, "/api/audit?actor=former@example.com")
	if len(pseudo.Items) != 0 {
		t.Fatalf("pseudonymized actor must not match old email, got %d rows", len(pseudo.Items))
	}
	all := auditViewerGetList(t, env, cookie, "/api/audit")
	foundFormer := false
	for _, item := range all.Items {
		if item.ActorID != nil && *item.ActorID == formerID.String() && item.ActorDisplay == "Former user" {
			foundFormer = true
		}
	}
	if !foundFormer {
		t.Fatal("pseudonymized actor did not render as Former user")
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

func insertAuditViewerRow(t *testing.T, env *TestEnv, eventType string, actorID *uuid.UUID, actorEmail string, targetType, targetID *string, outcome string) {
	t.Helper()
	var actor any
	if actorID != nil {
		actor = *actorID
	}
	email := any(nil)
	if actorEmail != "" {
		email = actorEmail
	}
	if _, err := env.Pool.Exec(context.Background(), `
		INSERT INTO audit_logs (event_type, actor_id, actor_email, target_type, target_id, outcome, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, '{}'::jsonb)
	`, eventType, actor, email, targetType, targetID, outcome); err != nil {
		t.Fatalf("insert audit row %s: %v", eventType, err)
	}
}

func ptr(s string) *string {
	return &s
}
