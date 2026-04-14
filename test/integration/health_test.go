package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/schlass/schlass/internal/handler"
)


func TestHealthCheckHealthy(t *testing.T) {
	env := NewTestEnv(t)
	h := handler.NewHealthHandler(env.Pool, env.ValkeyClient)

	req := httptest.NewRequest("GET", "/api/health", nil)
	rec := httptest.NewRecorder()
	h.GetHealth(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)

	if resp["status"] != "healthy" {
		t.Fatalf("expected status=healthy, got %s", resp["status"])
	}
	if resp["postgres"] != "up" {
		t.Fatalf("expected postgres=up, got %s", resp["postgres"])
	}
	if resp["valkey"] != "up" {
		t.Fatalf("expected valkey=up, got %s", resp["valkey"])
	}
}

func TestHealthCheckUnhealthyWhenValkeyDown(t *testing.T) {
	env := NewTestEnv(t)

	// Close valkey client to simulate it being down
	env.ValkeyClient.Close()

	h := handler.NewHealthHandler(env.Pool, env.ValkeyClient)

	req := httptest.NewRequest("GET", "/api/health", nil)
	rec := httptest.NewRecorder()
	h.GetHealth(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}

	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)

	if resp["status"] != "unhealthy" {
		t.Fatalf("expected status=unhealthy, got %s", resp["status"])
	}
	if resp["valkey"] != "down" {
		t.Fatalf("expected valkey=down, got %s", resp["valkey"])
	}
}
