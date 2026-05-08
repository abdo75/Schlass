package stream

import (
	"context"
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

// recordStreamer records every batch it receives; used in CAEPStreamer tests.
type recordStreamer struct {
	received [][]Event
	closed   bool
}

func (r *recordStreamer) Push(_ context.Context, batch []Event) error {
	r.received = append(r.received, batch)
	return nil
}

func (r *recordStreamer) Close() error {
	r.closed = true
	return nil
}

// TestCAEPStreamer_FiltersAndProjects verifies that only mapped events
// reach the inner streamer as JWS lines, and unmapped events are dropped.
func TestCAEPStreamer_FiltersAndProjects(t *testing.T) {
	inner := &recordStreamer{}

	// projSign: returns a fake JWS for session.revoked; false for login.succeeded.
	projSign := func(evt Event) (string, bool, error) {
		if evt.EventType == "session.revoked" {
			return "signed.jws." + evt.ID.String(), true, nil
		}
		return "", false, nil
	}

	cs := NewCAEPStreamer(inner, projSign)

	evtMapped := Event{
		ID:        uuid.New(),
		EventType: "session.revoked",
		Outcome:   "success",
	}
	evtUnmapped := Event{
		ID:        uuid.New(),
		EventType: "login.succeeded",
		Outcome:   "success",
	}

	if err := cs.Push(context.Background(), []Event{evtMapped, evtUnmapped}); err != nil {
		t.Fatalf("Push: %v", err)
	}

	if len(inner.received) != 1 {
		t.Fatalf("inner received %d batches, want 1", len(inner.received))
	}
	batch := inner.received[0]
	if len(batch) != 1 {
		t.Fatalf("batch len = %d, want 1 (unmapped should be filtered)", len(batch))
	}
	if batch[0].EventType != "signed.jws."+evtMapped.ID.String() {
		t.Errorf("EventType = %q, want JWS string", batch[0].EventType)
	}
}

// TestCAEPStreamer_AllUnmapped checks that inner.Push is not called when
// every event in the batch has no CAEP mapping.
func TestCAEPStreamer_AllUnmapped(t *testing.T) {
	inner := &recordStreamer{}
	projSign := func(evt Event) (string, bool, error) {
		return "", false, nil // nothing mapped
	}
	cs := NewCAEPStreamer(inner, projSign)
	evt := Event{ID: uuid.New(), EventType: "login.succeeded"}
	if err := cs.Push(context.Background(), []Event{evt}); err != nil {
		t.Fatalf("Push: %v", err)
	}
	if len(inner.received) != 0 {
		t.Errorf("inner.Push called despite all-unmapped batch")
	}
}
