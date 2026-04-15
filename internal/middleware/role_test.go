package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/abdo75/Schlass/internal/middleware"
	"github.com/abdo75/Schlass/internal/store"
	"github.com/google/uuid"
)

func TestRequireRole_AllowsMatchingRole(t *testing.T) {
	user := &store.User{ID: uuid.New(), Email: "admin@example.com", Role: "super_admin"}
	ctx := middleware.InjectUserForTest(context.Background(), user)

	handler := middleware.RequireRole("super_admin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequestWithContext(ctx, "GET", "/api/users", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRequireRole_RejectsOtherRole(t *testing.T) {
	user := &store.User{ID: uuid.New(), Email: "u@example.com", Role: "user"}
	ctx := middleware.InjectUserForTest(context.Background(), user)

	handler := middleware.RequireRole("super_admin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not run")
	}))

	req := httptest.NewRequestWithContext(ctx, "GET", "/api/users", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "FORBIDDEN") {
		t.Fatalf("want FORBIDDEN in body, got %s", rec.Body.String())
	}
}

func TestRequireRole_NoUserInContext_Returns401(t *testing.T) {
	// Simulating the impossible case where RequireRole is wired without
	// Auth being called first. Defensive check, not expected in production.
	handler := middleware.RequireRole("super_admin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not run")
	}))

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/api/users", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
}
