//go:build integration

package integration

import "testing"

func TestAuditListIncludesOwnViewedRowsUnderHostileFilter(t *testing.T) {
	env := NewTestEnv(t)
	adminID := env.SeedAdmin(t, "self-view@example.com", "CorrectHorse42!")
	cookie := env.LoginAsAdmin(t, "self-view@example.com", "CorrectHorse42!")
	insertAuditViewerRow(t, env, "login.succeeded", &adminID, "self-view@example.com", nil, nil, "success")

	first := auditViewerGetList(t, env, cookie, "/api/audit?event_types=login.succeeded")
	if len(first.Items) == 0 {
		t.Fatal("first filtered list returned no login rows")
	}
	second := auditViewerGetList(t, env, cookie, "/api/audit?event_types=login.succeeded")
	foundViewed := false
	for _, item := range second.Items {
		if item.EventType == "audit.viewed" && item.ActorID != nil && *item.ActorID == adminID.String() {
			foundViewed = true
		}
	}
	if !foundViewed {
		t.Fatal("second filtered list did not include caller's own audit.viewed row")
	}
}
