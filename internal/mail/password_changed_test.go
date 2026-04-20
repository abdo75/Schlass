package mail

import (
	"bytes"
	"html/template"
	"strings"
	"testing"
	texttemplate "text/template"
)

func TestSendPasswordChanged_RendersBothMIMEParts(t *testing.T) {
	htmlTpl, err := template.ParseFS(templatesFS, "templates/*.html.tmpl")
	if err != nil {
		t.Fatalf("parse html: %v", err)
	}
	textTpl, err := texttemplate.ParseFS(templatesFS, "templates/*.txt.tmpl")
	if err != nil {
		t.Fatalf("parse text: %v", err)
	}
	data := map[string]any{"InstanceName": "Acme", "EmailLocalPart": "alice"}
	var html, text bytes.Buffer
	if err := htmlTpl.ExecuteTemplate(&html, "password_changed.html.tmpl", data); err != nil {
		t.Fatalf("html exec: %v", err)
	}
	if err := textTpl.ExecuteTemplate(&text, "password_changed.txt.tmpl", data); err != nil {
		t.Fatalf("text exec: %v", err)
	}
	if !strings.Contains(html.String(), "Acme") || !strings.Contains(html.String(), "alice") {
		t.Fatalf("html missing substitutions: %s", html.String())
	}
	if !strings.Contains(text.String(), "Acme") || !strings.Contains(text.String(), "alice") {
		t.Fatalf("text missing substitutions: %s", text.String())
	}
	if !strings.Contains(text.String(), "Your password was changed") {
		t.Fatalf("text missing subject line: %s", text.String())
	}
}
