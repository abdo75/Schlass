// Package mail is Schlass's SMTP sender. Loads config from instance_config
// via ConfigService on construction; templates are embedded via go:embed.
//
// Used by:
//   - POST /api/settings/email/test (TestConnection)
//   - Sprint 6b M6 password-reset handler (SendPasswordReset — added in M6)
package mail

import (
	"bytes"
	"context"
	"crypto/tls"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/smtp"
	"strings"
	texttemplate "text/template"
	"time"

	"github.com/abdo75/Schlass/internal/config"
	"github.com/abdo75/Schlass/internal/database"
)

//go:embed templates/*.tmpl
var templatesFS embed.FS

// ErrSMTPConfigIncomplete indicates required SMTP fields (host/port/from)
// are unset. Handler translates to HTTP 400 SMTP_CONFIG_INCOMPLETE.
var ErrSMTPConfigIncomplete = errors.New("smtp config incomplete")

type Sender struct {
	host     string
	port     int
	username string
	password string
	from     string
	htmlTpl  *template.Template
	textTpl  *texttemplate.Template
}

// NewSenderFromConfig builds a Sender using the saved SMTP config.
// Returns ErrSMTPConfigIncomplete if required fields (host/port/from) are
// unset.
func NewSenderFromConfig(ctx context.Context, cfg *config.ConfigService, q database.Querier) (*Sender, error) {
	snap, err := cfg.GetSettingsSnapshot(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("settings snapshot: %w", err)
	}
	if snap.Email.SMTPHost == "" || snap.Email.SMTPPort == 0 || snap.Email.SMTPFrom == "" {
		return nil, ErrSMTPConfigIncomplete
	}
	pw, err := cfg.GetEncryptedValue(ctx, q, "smtp_password")
	if err != nil {
		return nil, fmt.Errorf("decrypt smtp_password: %w", err)
	}
	htmlTpl, err := template.ParseFS(templatesFS, "templates/*.html.tmpl")
	if err != nil {
		return nil, fmt.Errorf("parse html templates: %w", err)
	}
	textTpl, err := texttemplate.ParseFS(templatesFS, "templates/*.txt.tmpl")
	if err != nil {
		return nil, fmt.Errorf("parse text templates: %w", err)
	}
	return &Sender{
		host:     snap.Email.SMTPHost,
		port:     snap.Email.SMTPPort,
		username: snap.Email.SMTPUsername,
		password: pw,
		from:     snap.Email.SMTPFrom,
		htmlTpl:  htmlTpl,
		textTpl:  textTpl,
	}, nil
}

// TestConnection sends a fixed "test connection" email to the `to` address.
// Used by POST /api/settings/email/test.
func (s *Sender) TestConnection(ctx context.Context, to, instanceName string) error {
	data := map[string]any{
		"InstanceName": instanceName,
		"SentAt":       time.Now().UTC().Format(time.RFC3339),
	}
	var html, text bytes.Buffer
	if err := s.htmlTpl.ExecuteTemplate(&html, "test_connection.html.tmpl", data); err != nil {
		return fmt.Errorf("render html: %w", err)
	}
	if err := s.textTpl.ExecuteTemplate(&text, "test_connection.txt.tmpl", data); err != nil {
		return fmt.Errorf("render text: %w", err)
	}
	subject := "Schlass SMTP test — " + instanceName
	return s.send(ctx, to, subject, html.Bytes(), text.Bytes())
}

// SendPasswordReset emails a reset link to `to`. token is the plaintext
// 32-byte base64url token; publicURL is SCHLASS_PUBLIC_URL; the final
// URL is {publicURL}/reset-password/{token}. Email local-part (the bit
// before @) is used as the "Hi <name>" greeting since users.name does
// not exist in v1.
func (s *Sender) SendPasswordReset(ctx context.Context, to, token, instanceName, publicURL string) error {
	localPart := to
	if idx := strings.IndexByte(to, '@'); idx > 0 {
		localPart = to[:idx]
	}
	resetURL := publicURL + "/reset-password/" + token
	data := map[string]any{
		"InstanceName":   instanceName,
		"EmailLocalPart": localPart,
		"ResetURL":       resetURL,
	}
	var html, text bytes.Buffer
	if err := s.htmlTpl.ExecuteTemplate(&html, "password_reset.html.tmpl", data); err != nil {
		return fmt.Errorf("render html: %w", err)
	}
	if err := s.textTpl.ExecuteTemplate(&text, "password_reset.txt.tmpl", data); err != nil {
		return fmt.Errorf("render text: %w", err)
	}
	subject := "Reset your " + instanceName + " password"
	return s.send(ctx, to, subject, html.Bytes(), text.Bytes())
}

// send assembles a multipart/alternative MIME message and dispatches via
// STARTTLS when the server advertises it. Unencrypted delivery permitted
// for localhost dev (MailHog, testcontainers).
func (s *Sender) send(ctx context.Context, to, subject string, html, text []byte) error {
	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	boundary := "schlass-" + time.Now().Format("20060102150405.000")

	msg := bytes.Buffer{}
	fmt.Fprintf(&msg, "From: %s\r\n", s.from)
	fmt.Fprintf(&msg, "To: %s\r\n", to)
	fmt.Fprintf(&msg, "Subject: %s\r\n", subject)
	msg.WriteString("MIME-Version: 1.0\r\n")
	fmt.Fprintf(&msg, "Content-Type: multipart/alternative; boundary=%s\r\n", boundary)
	msg.WriteString("\r\n")
	fmt.Fprintf(&msg, "--%s\r\n", boundary)
	msg.WriteString("Content-Type: text/plain; charset=utf-8\r\n\r\n")
	msg.Write(text)
	fmt.Fprintf(&msg, "\r\n--%s\r\n", boundary)
	msg.WriteString("Content-Type: text/html; charset=utf-8\r\n\r\n")
	msg.Write(html)
	fmt.Fprintf(&msg, "\r\n--%s--\r\n", boundary)

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("dial smtp: %w", err)
	}
	c, err := smtp.NewClient(conn, s.host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp client: %w", err)
	}
	defer func() { _ = c.Quit() }()

	if ok, _ := c.Extension("STARTTLS"); ok {
		tlsCfg := &tls.Config{ServerName: s.host, MinVersion: tls.VersionTLS12}
		if err := c.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	}
	if s.username != "" {
		auth := smtp.PlainAuth("", s.username, s.password, s.host)
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	}
	if err := c.Mail(s.from); err != nil {
		return fmt.Errorf("mail from: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("rcpt: %w", err)
	}
	wc, err := c.Data()
	if err != nil {
		return fmt.Errorf("data: %w", err)
	}
	if _, err := wc.Write(msg.Bytes()); err != nil {
		_ = wc.Close()
		return fmt.Errorf("write body: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("close body: %w", err)
	}
	return nil
}
