package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/abdo75/Schlass/internal/audit/stream"
)

// fixture is the shape stored in testdata/caep/<event_type>.json.
type caepFixture struct {
	URN             string `json:"urn"`
	InitiatingEntity string `json:"initiating_entity,omitempty"`
	ReasonAdmin     string `json:"reason_admin,omitempty"`
	CredentialType  string `json:"credential_type,omitempty"`
	ChangeType      string `json:"change_type,omitempty"`
	Reason          string `json:"reason,omitempty"`
	CurrentLevel    string `json:"current_level,omitempty"`
	PreviousLevel   string `json:"previous_level,omitempty"`
}

func loadFixture(t *testing.T, eventType string) caepFixture {
	t.Helper()
	path := filepath.Join("testdata", "caep", eventType+".json")
	// G304: path is testdata-relative; only test code reads it.
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		t.Fatalf("load fixture %s: %v", path, err)
	}
	var f caepFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse fixture %s: %v", path, err)
	}
	return f
}

func makeRow(eventType string) stream.Event {
	_ = uuid.New() // unused in system-actor path; quiets import
	return stream.Event{
		ID:             uuid.New(),
		TenantID:       SingleTenant,
		SequenceNo:     1,
		EventType:      eventType,
		EventTimestamp: time.Unix(1700000000, 0),
		Outcome:        "success",
		ActorType:      string(ActorTypeSystem),
		ActorID:        nil, // system-initiated by default
	}
}

func makeUserRow(eventType string) stream.Event {
	actorID := uuid.New()
	targetID := uuid.New().String()
	r := makeRow(eventType)
	r.ActorType = string(ActorTypeUser)
	r.ActorID = &actorID
	r.TargetType = strPtr("user")
	r.TargetID = &targetID
	return r
}

func strPtr(s string) *string { return &s }

// TestProjectCAEP_Coverage checks every event_type that has an OutboundCAEP
// mapping produces ok=true and URN matches the fixture.
func TestProjectCAEP_Coverage(t *testing.T) {
	const issuer = "https://auth.example.com"
	cases := []struct {
		eventType string
		mkRow     func(string) stream.Event
	}{
		{"account.locked", makeRow},
		{"password.changed", makeUserRow},
		{"password_reset.completed", makeUserRow},
		{"session.revoked", makeRow},
		{"session.terminated", makeRow},
		{"oidc.refresh.reuse_detected", makeRow},
		{"client.secret_rotated", makeRow},
		{"user.disabled", makeUserRow},
		{"user.password_reset", makeUserRow},
		{"user.revoke_before_set", makeRow},
		{"user.sessions_terminated", makeRow},
	}

	for _, c := range cases {
		t.Run(c.eventType, func(t *testing.T) {
			row := c.mkRow(c.eventType)
			claims, urn, ok, err := ProjectCAEP(row, issuer)
			if err != nil {
				t.Fatalf("ProjectCAEP error: %v", err)
			}
			if !ok {
				t.Fatalf("ProjectCAEP returned ok=false, want ok=true")
			}

			fix := loadFixture(t, c.eventType)
			if urn != fix.URN {
				t.Errorf("urn = %q, want %q", urn, fix.URN)
			}

			// Basic RFC 8417 envelope checks.
			if claims["iss"] != issuer {
				t.Errorf("iss = %v, want %q", claims["iss"], issuer)
			}
			if claims["jti"] != row.ID.String() {
				t.Errorf("jti mismatch")
			}
			events, _ := claims["events"].(map[string]any)
			payload, _ := events[urn].(map[string]any)
			if payload == nil {
				t.Fatalf("events[%q] missing", urn)
			}

			// Per-URN specific claims from fixture.
			assertStr := func(key, want string) {
				t.Helper()
				if want == "" {
					return
				}
				got, _ := payload[key].(string)
				if got != want {
					t.Errorf("payload[%q] = %q, want %q", key, got, want)
				}
			}
			assertStr("initiating_entity", fix.InitiatingEntity)
			assertStr("credential_type", fix.CredentialType)
			assertStr("change_type", fix.ChangeType)
			assertStr("reason", fix.Reason)
			assertStr("current_level", fix.CurrentLevel)
			assertStr("previous_level", fix.PreviousLevel)
		})
	}
}

// TestProjectCAEP_Unmapped confirms ok=false for an event with no mapping.
func TestProjectCAEP_Unmapped(t *testing.T) {
	row := makeRow("login.succeeded")
	_, _, ok, err := ProjectCAEP(row, "https://iss")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected ok=false for unmapped event, got true")
	}
}

// TestProjectCAEP_ReasonCode checks reason_admin is forwarded when present.
func TestProjectCAEP_ReasonCode(t *testing.T) {
	row := makeRow("session.revoked")
	reason := "policy:idle_timeout"
	row.ReasonCode = &reason

	claims, urn, ok, err := ProjectCAEP(row, "https://iss")
	if err != nil || !ok {
		t.Fatalf("ProjectCAEP error/not ok: %v %v", err, ok)
	}
	events, _ := claims["events"].(map[string]any)
	payload, _ := events[urn].(map[string]any)
	if got := payload["reason_admin"]; got != reason {
		t.Errorf("reason_admin = %v, want %q", got, reason)
	}
}
