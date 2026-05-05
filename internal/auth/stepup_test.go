package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/abdo75/Schlass/internal/auth"
	"github.com/abdo75/Schlass/internal/session"
	"github.com/abdo75/Schlass/internal/users"
)

type stepUpSessionStore struct {
	sess *session.Session
	err  error
}

func (s *stepUpSessionStore) Create(context.Context, string, string, string) (string, error) {
	return "", nil
}
func (s *stepUpSessionStore) Get(context.Context, string) (*session.Session, error) {
	return s.sess, s.err
}
func (s *stepUpSessionStore) Delete(context.Context, string, string) error { return nil }
func (s *stepUpSessionStore) ListByUser(context.Context, string) ([]*session.SessionWithToken, error) {
	return nil, nil
}
func (s *stepUpSessionStore) DeleteAllForUser(context.Context, string) error { return nil }
func (s *stepUpSessionStore) CreateWithPendingReturnTo(context.Context, string, string, string, string) (string, error) {
	return "", nil
}
func (s *stepUpSessionStore) ClearPendingReturnTo(context.Context, string) error { return nil }
func (s *stepUpSessionStore) MarkAuditViewed(context.Context, string) error      { return nil }
func (s *stepUpSessionStore) MarkMFAVerified(context.Context, string) error      { return nil }

func TestRequireRecentMFA_AllowsFreshSession(t *testing.T) {
	store := &stepUpSessionStore{sess: &session.Session{LastMFAAt: time.Now().UTC()}}
	handler := auth.RequireRecentMFA(5*time.Minute, store, nil, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := stepUpRequest()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRequireRecentMFA_RejectsStaleSession(t *testing.T) {
	store := &stepUpSessionStore{sess: &session.Session{LastMFAAt: time.Now().UTC().Add(-6 * time.Minute)}}
	handler := auth.RequireRecentMFA(5*time.Minute, store, nil, nil)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler should not run")
	}))
	req := stepUpRequest()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "STEPUP_REQUIRED") {
		t.Fatalf("want STEPUP_REQUIRED body, got %s", rec.Body.String())
	}
}

func TestRequireRecentMFA_RejectsMissingLastMFA(t *testing.T) {
	store := &stepUpSessionStore{sess: &session.Session{}}
	handler := auth.RequireRecentMFA(5*time.Minute, store, nil, nil)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler should not run")
	}))
	req := stepUpRequest()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "STEPUP_REQUIRED") {
		t.Fatalf("want STEPUP_REQUIRED body, got %s", rec.Body.String())
	}
}

func stepUpRequest() *http.Request {
	u := &users.User{ID: uuid.New(), Email: "admin@example.com", Role: "super_admin"}
	ctx := session.WithToken(users.WithCurrentUser(context.Background(), u), "session-token")
	return httptest.NewRequestWithContext(ctx, "POST", "/api/audit/export", nil)
}
