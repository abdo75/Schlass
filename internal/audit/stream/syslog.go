package stream

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SyslogStreamer delivers audit events as RFC 5424 messages over a
// TLS-secured TCP connection, octet-counting framed per RFC 6587 §3.4.1.
// Plain TCP is intentionally unsupported: audit events identify users
// and resources, so plaintext on the wire is never acceptable.
//
// SD-ID `schlass-audit@99999` carries the structured-data fields. The
// 99999 enterprise-number placeholder must be replaced with the
// operator's IANA-assigned PEN before federation.
//
// TODO(operator): replace `schlass-audit@99999` with assigned IANA PEN.
type SyslogStreamer struct {
	endpoint string
	tlsCfg   *tls.Config
	hostname string
	pid      string

	mu   sync.Mutex
	conn net.Conn
}

// NewSyslogStreamer constructs a streamer pointed at host:port.
// dialer (the connection setup) is lazy: the first Push opens the
// connection and re-opens it after any write error.
func NewSyslogStreamer(endpoint string, tlsCfg *tls.Config) (*SyslogStreamer, error) {
	if endpoint == "" {
		return nil, errors.New("syslog: empty endpoint")
	}
	if strings.HasPrefix(endpoint, "tcp://") {
		return nil, errors.New("syslog: plain tcp:// is not supported, use TLS-only host:port")
	}
	endpoint = strings.TrimPrefix(endpoint, "tls://")
	if _, _, err := net.SplitHostPort(endpoint); err != nil {
		return nil, fmt.Errorf("syslog: invalid endpoint %q: %w", endpoint, err)
	}
	host, _ := os.Hostname()
	return &SyslogStreamer{
		endpoint: endpoint,
		tlsCfg:   tlsCfg,
		hostname: nilToHyphen(host),
		pid:      strconv.Itoa(os.Getpid()),
	}, nil
}

// Push writes every event in batch in order. The whole batch fails on
// the first write error so the worker re-pushes the same batch after
// re-connecting; receivers dedupe by event_id.
func (s *SyslogStreamer) Push(ctx context.Context, batch []Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureConn(ctx); err != nil {
		return err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(PushTimeout)
	}
	if err := s.conn.SetWriteDeadline(deadline); err != nil {
		return fmt.Errorf("syslog: set deadline: %w", err)
	}
	for _, e := range batch {
		msg := formatRFC5424(s.hostname, s.pid, e)
		frame := append([]byte(strconv.Itoa(len(msg))+" "), msg...)
		if _, err := s.conn.Write(frame); err != nil {
			// Drop the connection so the next Push reconnects fresh.
			_ = s.conn.Close()
			s.conn = nil
			return fmt.Errorf("syslog: write: %w", err)
		}
	}
	return nil
}

// Close drops the cached connection. Safe to call multiple times.
func (s *SyslogStreamer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		err := s.conn.Close()
		s.conn = nil
		return err
	}
	return nil
}

func (s *SyslogStreamer) ensureConn(ctx context.Context) error {
	if s.conn != nil {
		return nil
	}
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: PushTimeout},
		Config:    s.tlsCfg,
	}
	conn, err := dialer.DialContext(ctx, "tcp", s.endpoint)
	if err != nil {
		return fmt.Errorf("syslog: dial: %w", err)
	}
	s.conn = conn
	return nil
}

// formatRFC5424 builds one syslog message:
//
//	<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
//
// MSG is the literal "-" — every field of interest lives in SD so the
// receiver doesn't have to grep the free-form body.
//
// PRI = facility*8 + severity. Facility 13 = "log audit" per the RFC
// 3164 numeric table that RFC 5424 inherits. Severity 6 = informational
// for success/denied outcomes, 3 = error for failure.
func formatRFC5424(hostname, pid string, e Event) string {
	severity := 6
	if e.Outcome == "failure" {
		severity = 3
	}
	pri := 13*8 + severity

	var b bytes.Buffer
	fmt.Fprintf(&b, "<%d>1 %s %s schlass-audit %s %s ",
		pri,
		e.EventTimestamp.UTC().Format(time.RFC3339Nano),
		hostname,
		pid,
		nilToHyphen(e.EventType),
	)
	b.WriteString(formatStructuredData(e))
	b.WriteString(" -")
	return b.String()
}

func formatStructuredData(e Event) string {
	var b bytes.Buffer
	b.WriteString("[schlass-audit@99999")
	addSDParam(&b, "event_id", e.ID.String())
	addSDParam(&b, "tenant_id", e.TenantID.String())
	addSDParam(&b, "sequence_no", strconv.FormatInt(e.SequenceNo, 10))
	addSDParam(&b, "outcome", e.Outcome)
	addSDParam(&b, "actor_type", e.ActorType)
	if e.ActorID != nil {
		addSDParam(&b, "actor_id", e.ActorID.String())
	}
	if e.TargetType != nil {
		addSDParam(&b, "target_type", *e.TargetType)
	}
	if e.TargetID != nil {
		addSDParam(&b, "target_id", *e.TargetID)
	}
	if e.ReasonCode != nil {
		addSDParam(&b, "reason_code", *e.ReasonCode)
	}
	addSDParam(&b, "source_service", e.SourceService)
	b.WriteString("]")
	return b.String()
}

func addSDParam(b *bytes.Buffer, k, v string) {
	if v == "" {
		return
	}
	b.WriteByte(' ')
	b.WriteString(k)
	b.WriteString("=\"")
	b.WriteString(escapeSDValue(v))
	b.WriteString("\"")
}

// escapeSDValue escapes the three characters reserved inside an SD-PARAM
// value: `"`, `\`, `]`. Per RFC 5424 §6.3.3.
func escapeSDValue(v string) string {
	if !strings.ContainsAny(v, `"\]`) {
		return v
	}
	var b strings.Builder
	b.Grow(len(v) + 4)
	for _, r := range v {
		switch r {
		case '"', '\\', ']':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func nilToHyphen(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
