package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/abdo75/Schlass/internal/middleware"
	"github.com/abdo75/Schlass/internal/store"
	"github.com/google/uuid"
)

func TestRequirePermission_AllowsPermittedUser(t *testing.T) {
	user := &store.User{ID: uuid.New(), Email: "admin@example.com", Role: "super_admin"}
	ctx := middleware.InjectUserForTest(context.Background(), user)

	handler := middleware.RequirePermission("users.create")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequestWithContext(ctx, "POST", "/api/users", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRequirePermission_RejectsUnpermittedRole(t *testing.T) {
	user := &store.User{ID: uuid.New(), Email: "u@example.com", Role: "user"}
	ctx := middleware.InjectUserForTest(context.Background(), user)

	handler := middleware.RequirePermission("users.create")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not run")
	}))

	req := httptest.NewRequestWithContext(ctx, "POST", "/api/users", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "FORBIDDEN") {
		t.Fatalf("want FORBIDDEN in body, got %s", rec.Body.String())
	}
}

func TestRequirePermission_NoUserInContext_Returns401(t *testing.T) {
	handler := middleware.RequirePermission("users.create")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not run")
	}))

	req := httptest.NewRequestWithContext(context.Background(), "POST", "/api/users", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "INVALID_SESSION") {
		t.Fatalf("want INVALID_SESSION in body, got %s", rec.Body.String())
	}
}

func TestRequirePermission_UnknownRole_Rejects(t *testing.T) {
	// Defensive: a role string that was not in rolePermissions must 403, never
	// accidentally pass. Guards against typos in future role additions.
	user := &store.User{ID: uuid.New(), Email: "x@example.com", Role: "typo_role"}
	ctx := middleware.InjectUserForTest(context.Background(), user)

	handler := middleware.RequirePermission("users.create")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not run")
	}))

	req := httptest.NewRequestWithContext(ctx, "POST", "/api/users", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", rec.Code)
	}
}

func TestPermissionsForRole(t *testing.T) {
	sa := middleware.PermissionsForRole("super_admin")
	if len(sa) == 0 {
		t.Fatal("super_admin should hold a non-empty permission set")
	}
	// Assert representative permissions are present — verifies the mapping
	// is correctly wired without hardcoding a count that would false-fail on
	// every future permission addition.
	for _, required := range []string{"users.list", "users.create", "users.sessions.terminate", "users.reset_mfa", "signing_keys.rotate"} {
		if !slices.Contains(sa, required) {
			t.Errorf("super_admin missing required permission %q", required)
		}
	}

	u := middleware.PermissionsForRole("user")
	if len(u) != 0 {
		t.Fatalf("user should hold 0 permissions, got %d", len(u))
	}
	unknown := middleware.PermissionsForRole("nope")
	if len(unknown) != 0 {
		t.Fatalf("unknown role should hold 0 permissions, got %d", len(unknown))
	}
}
