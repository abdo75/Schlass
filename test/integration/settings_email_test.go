//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// mailHogContainer is a per-test MailHog instance — the only test tier that
// needs a real SMTP server. Launched per-test (not shared) because the TEST
// endpoint leaves a message behind and the assertion wants an empty inbox
// as a starting state.
type mailHogContainer struct {
	container testcontainers.Container
	host      string
	smtpPort  int
	apiPort   int
}

func startMailHog(t *testing.T) *mailHogContainer {
	t.Helper()
	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "mailhog/mailhog:v1.0.1",
		ExposedPorts: []string{"1025/tcp", "8025/tcp"},
		WaitingFor:   wait.ForListeningPort("1025/tcp").WithStartupTimeout(30 * time.Second),
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: req, Started: true})
	if err != nil {
		t.Fatalf("mailhog start: %v", err)
	}
	host, _ := c.Host(ctx)
	smtpP, _ := c.MappedPort(ctx, "1025/tcp")
	apiP, _ := c.MappedPort(ctx, "8025/tcp")
	smtpInt, _ := strconv.Atoi(smtpP.Port())
	apiInt, _ := strconv.Atoi(apiP.Port())
	return &mailHogContainer{container: c, host: host, smtpPort: smtpInt, apiPort: apiInt}
}

func (m *mailHogContainer) stop(t *testing.T) {
	if err := m.container.Terminate(context.Background()); err != nil {
		t.Logf("mailhog stop: %v", err)
	}
}

// waitForMessage polls MailHog's /api/v2/messages endpoint until at least
// one message lands or the timeout expires. Returns the raw JSON body.
func (m *mailHogContainer) waitForMessage(t *testing.T, timeout time.Duration) map[string]any {
	t.Helper()
	deadline := time.Now().Add(timeout)
	url := fmt.Sprintf("http://%s:%d/api/v2/messages", m.host, m.apiPort)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			var out map[string]any
			if err := json.Unmarshal(b, &out); err == nil {
				if items, ok := out["items"].([]any); ok && len(items) > 0 {
					return out
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("no mailhog message within %v", timeout)
	return nil
}

// TestSettingsEmailTest_Delivered exercises the happy path: admin saves SMTP
// config pointing at MailHog, fires POST /api/settings/email/test, and the
// MailHog HTTP API reports a delivered message containing the template
// markers. This is the only test tier in the stack that proves the full
// SMTP handshake works end-to-end — handler-level assertions alone can't
// distinguish "sent" from "fake-sent".
func TestSettingsEmailTest_Delivered(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	mh := startMailHog(t)
	defer mh.stop(t)

	env.SeedAdmin(t, "admin@example.com", "CorrectHorse1Battery")
	adminCookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse1Battery")

	// Save SMTP config pointing at MailHog.
	body, _ := json.Marshal(map[string]any{
		"smtp_host":     mh.host,
		"smtp_port":     mh.smtpPort,
		"smtp_username": "",
		"smtp_password": "",
		"smtp_from":     "no-reply@schlass.test",
	})
	saveResp := adminPatch(t, env, adminCookie, "/api/settings/email", body)
	if saveResp.Code != http.StatusOK {
		t.Fatalf("save config: got %d, want 200, body: %s", saveResp.Code, saveResp.Body.String())
	}

	// Trigger the test endpoint.
	testResp := adminPost(t, env, adminCookie, "/api/settings/email/test", nil)
	if testResp.Code != http.StatusOK {
		t.Fatalf("test endpoint: got %d, want 200, body: %s", testResp.Code, testResp.Body.String())
	}

	// Response body should carry a delivered_at timestamp.
	var okResp map[string]any
	if err := json.Unmarshal(testResp.Body.Bytes(), &okResp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if _, ok := okResp["delivered_at"].(string); !ok {
		t.Fatalf("response missing delivered_at: %v", okResp)
	}

	// Poll MailHog for the delivered message.
	body2 := mh.waitForMessage(t, 5*time.Second)
	items, _ := body2["items"].([]any)
	if len(items) < 1 {
		t.Fatalf("no messages in MailHog")
	}

	// Spot-check: the MIME body preserves the subject and template body.
	envStr, _ := json.Marshal(items[0])
	combined := string(envStr)
	for _, want := range []string{"SMTP test", "Schlass SMTP configuration"} {
		if !strings.Contains(combined, want) {
			t.Fatalf("message body missing %q: %s", want, combined)
		}
	}
}

// TestSettingsEmailTest_IncompleteConfig verifies that firing the test
// endpoint without any saved SMTP config returns 400 with the
// SMTP_CONFIG_INCOMPLETE code. This is the failure-path the Email tab
// uses to render a "save SMTP config first" helper message.
func TestSettingsEmailTest_IncompleteConfig(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()

	env.SeedAdmin(t, "admin@example.com", "CorrectHorse1Battery")
	adminCookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse1Battery")
	// Do NOT seed SMTP config.
	resp := adminPost(t, env, adminCookie, "/api/settings/email/test", nil)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400, body: %s", resp.Code, resp.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out["error"] != "SMTP_CONFIG_INCOMPLETE" {
		t.Fatalf("error code = %q, want SMTP_CONFIG_INCOMPLETE", out["error"])
	}
}
