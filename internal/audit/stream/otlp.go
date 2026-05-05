package stream

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// OTLPStreamer pushes audit events as OTLP/HTTP Logs JSON. We
// hand-roll the payload (rather than depend on the OTel SDK) because
// the schema is small and the SDK pulls in a heavy graph of indirect
// dependencies for what amounts to one HTTP call.
//
// The schema follows the OTLP Logs Data Model 1.0:
// https://opentelemetry.io/docs/specs/otlp/#otlphttp
//
// Endpoint is the full URL terminating at the receiver
// (e.g. https://otelcol.example.com/v1/logs). bearerToken, when
// non-empty, is sent verbatim as `Authorization: Bearer <token>`.
type OTLPStreamer struct {
	endpoint    string
	bearerToken string
	client      *http.Client
}

// NewOTLPStreamer requires a non-empty https endpoint. http:// is
// permitted only because some operators front the receiver with a
// service-mesh sidecar that terminates TLS upstream — but the streamer
// logs a warning at boot if the URL scheme is plain http.
func NewOTLPStreamer(endpoint, bearerToken string) (*OTLPStreamer, error) {
	if endpoint == "" {
		return nil, errors.New("otlp: empty endpoint")
	}
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		return nil, fmt.Errorf("otlp: endpoint %q must start with http:// or https://", endpoint)
	}
	return &OTLPStreamer{
		endpoint:    endpoint,
		bearerToken: bearerToken,
		client:      &http.Client{Timeout: PushTimeout},
	}, nil
}

// Push serialises the batch to one OTLP request and POSTs it. 2xx is
// success; any other status (or transport error) returns an error so
// the worker can DLQ the batch.
func (o *OTLPStreamer) Push(ctx context.Context, batch []Event) error {
	if len(batch) == 0 {
		return nil
	}
	body, err := json.Marshal(buildOTLPPayload(batch))
	if err != nil {
		return fmt.Errorf("otlp: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("otlp: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if o.bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+o.bearerToken)
	}
	resp, err := o.client.Do(req)
	if err != nil {
		return fmt.Errorf("otlp: post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		preview, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("otlp: status %d: %s", resp.StatusCode, string(preview))
	}
	return nil
}

// Close is a no-op (the underlying http.Client has no resources to
// release; idle connections drain on their own).
func (o *OTLPStreamer) Close() error { return nil }

// otlpPayload + nested types mirror the JSON keys defined by the
// OTLP/HTTP spec. Field tags are deliberately CamelCase-to-snake to
// match the spec verbatim.
type otlpPayload struct {
	ResourceLogs []otlpResourceLogs `json:"resourceLogs"`
}

type otlpResourceLogs struct {
	Resource  otlpResource    `json:"resource"`
	ScopeLogs []otlpScopeLogs `json:"scopeLogs"`
}

type otlpResource struct {
	Attributes []otlpAttr `json:"attributes"`
}

type otlpScopeLogs struct {
	Scope      otlpScope    `json:"scope"`
	LogRecords []otlpRecord `json:"logRecords"`
}

type otlpScope struct {
	Name string `json:"name"`
}

type otlpRecord struct {
	TimeUnixNano   string     `json:"timeUnixNano"`
	SeverityNumber int        `json:"severityNumber"`
	SeverityText   string     `json:"severityText"`
	Body           otlpValue  `json:"body"`
	Attributes     []otlpAttr `json:"attributes"`
}

type otlpAttr struct {
	Key   string    `json:"key"`
	Value otlpValue `json:"value"`
}

type otlpValue struct {
	StringValue string `json:"stringValue"`
}

func buildOTLPPayload(batch []Event) otlpPayload {
	records := make([]otlpRecord, 0, len(batch))
	for _, e := range batch {
		sevNum, sevText := otlpSeverity(e.Outcome)
		records = append(records, otlpRecord{
			TimeUnixNano:   strconv.FormatInt(e.EventTimestamp.UTC().UnixNano(), 10),
			SeverityNumber: sevNum,
			SeverityText:   sevText,
			Body:           otlpValue{StringValue: e.EventType},
			Attributes:     buildAttrs(e),
		})
	}
	return otlpPayload{
		ResourceLogs: []otlpResourceLogs{{
			Resource: otlpResource{Attributes: []otlpAttr{
				{Key: "service.name", Value: otlpValue{StringValue: "schlass-audit"}},
			}},
			ScopeLogs: []otlpScopeLogs{{
				Scope:      otlpScope{Name: "schlass.audit"},
				LogRecords: records,
			}},
		}},
	}
}

func otlpSeverity(outcome string) (int, string) {
	if outcome == "failure" {
		return 17, "ERROR"
	}
	return 9, "INFO"
}

func buildAttrs(e Event) []otlpAttr {
	out := []otlpAttr{
		{Key: "event.id", Value: otlpValue{StringValue: e.ID.String()}},
		{Key: "audit.tenant_id", Value: otlpValue{StringValue: e.TenantID.String()}},
		{Key: "audit.sequence_no", Value: otlpValue{StringValue: strconv.FormatInt(e.SequenceNo, 10)}},
		{Key: "audit.outcome", Value: otlpValue{StringValue: e.Outcome}},
		{Key: "audit.actor_type", Value: otlpValue{StringValue: e.ActorType}},
		{Key: "audit.source_service", Value: otlpValue{StringValue: e.SourceService}},
	}
	if e.ActorID != nil {
		out = append(out, otlpAttr{Key: "audit.actor_id", Value: otlpValue{StringValue: e.ActorID.String()}})
	}
	if e.TargetType != nil {
		out = append(out, otlpAttr{Key: "audit.target_type", Value: otlpValue{StringValue: *e.TargetType}})
	}
	if e.TargetID != nil {
		out = append(out, otlpAttr{Key: "audit.target_id", Value: otlpValue{StringValue: *e.TargetID}})
	}
	if e.ReasonCode != nil {
		out = append(out, otlpAttr{Key: "audit.reason_code", Value: otlpValue{StringValue: *e.ReasonCode}})
	}
	return out
}
