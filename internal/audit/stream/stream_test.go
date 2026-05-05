package stream

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestBackoffCurve(t *testing.T) {
	cases := []struct {
		attempt int
		want    time.Duration
	}{
		{0, 1 * time.Minute},
		{1, 1 * time.Minute},
		{2, 2 * time.Minute},
		{3, 5 * time.Minute},
		{4, 15 * time.Minute},
		{5, 1 * time.Hour},
		{6, 6 * time.Hour},
		{7, 24 * time.Hour},
		{8, 24 * time.Hour}, // bounded at last entry
		{99, 24 * time.Hour},
	}
	for _, c := range cases {
		got := Backoff(c.attempt)
		if got != c.want {
			t.Errorf("Backoff(%d) = %v, want %v", c.attempt, got, c.want)
		}
	}
}

func TestRFC5424_FramingAndSDEscape(t *testing.T) {
	tid := uuid.New()
	aid := uuid.New()
	target := `weird"value\with]chars`
	e := Event{
		ID:             uuid.New(),
		TenantID:       tid,
		SequenceNo:     42,
		EventType:      "login.failed",
		EventTimestamp: time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC),
		Outcome:        "failure",
		ActorType:      "user",
		ActorID:        &aid,
		TargetType:     ptr("user"),
		TargetID:       &target,
		SourceService:  "auth",
	}
	msg := formatRFC5424("test-host", "9999", e)

	// PRI = 13*8 + 3 = 107 for failure.
	if !strings.HasPrefix(msg, "<107>1 ") {
		t.Errorf("PRI prefix wrong: %q", msg[:10])
	}
	// Expect quoted SD-PARAM with backslash-escaped chars in the value.
	if !strings.Contains(msg, `target_id="weird\"value\\with\]chars"`) {
		t.Errorf("SD value not escaped: %s", msg)
	}
	if !strings.Contains(msg, "sequence_no=\"42\"") {
		t.Errorf("missing sequence_no: %s", msg)
	}
	if !strings.HasSuffix(msg, " -") {
		t.Errorf("missing empty MSG suffix: %s", msg)
	}
}

func TestOTLPPayloadShape(t *testing.T) {
	tid := uuid.New()
	aid := uuid.New()
	e := Event{
		ID:             uuid.New(),
		TenantID:       tid,
		SequenceNo:     7,
		EventType:      "session.revoked",
		EventTimestamp: time.Unix(1700000000, 0),
		Outcome:        "success",
		ActorType:      "user",
		ActorID:        &aid,
		SourceService:  "session",
	}
	payload := buildOTLPPayload([]Event{e})
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(body)
	for _, want := range []string{
		`"resourceLogs"`,
		`"service.name"`,
		`"schlass-audit"`,
		`"scopeLogs"`,
		`"schlass.audit"`,
		`"logRecords"`,
		`"timeUnixNano"`,
		`"severityNumber":9`,
		`"severityText":"INFO"`,
		`"stringValue":"session.revoked"`,
		`"audit.actor_id"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("payload missing %q\nfull: %s", want, s)
		}
	}
}

func TestOTLPSeverity(t *testing.T) {
	if n, txt := otlpSeverity("success"); n != 9 || txt != "INFO" {
		t.Errorf("success → (%d, %q), want (9, INFO)", n, txt)
	}
	if n, txt := otlpSeverity("denied"); n != 9 || txt != "INFO" {
		t.Errorf("denied → (%d, %q), want (9, INFO)", n, txt)
	}
	if n, txt := otlpSeverity("failure"); n != 17 || txt != "ERROR" {
		t.Errorf("failure → (%d, %q), want (17, ERROR)", n, txt)
	}
}

func ptr[T any](v T) *T { return &v }
