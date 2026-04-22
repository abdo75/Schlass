package crypto

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHIBPChecker_PwnedPassword(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/5BAA6" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if got := r.Header.Get("Add-Padding"); got != "true" {
			t.Errorf("Add-Padding header = %q, want %q", got, "true")
		}
		if got := r.Header.Get("User-Agent"); !strings.HasPrefix(got, "schlass-hibp/") {
			t.Errorf("User-Agent = %q, want schlass-hibp/ prefix", got)
		}
		_, _ = fmt.Fprintln(w, "003D68EB55068C33ACE09247EE4C639306B:3")
		_, _ = fmt.Fprintln(w, "1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824")
		_, _ = fmt.Fprintln(w, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0")
	}))
	defer srv.Close()

	c := &HIBPChecker{Endpoint: srv.URL}
	got, err := c.IsPwned(context.Background(), "password")
	if err != nil {
		t.Fatalf("IsPwned: %v", err)
	}
	if !got {
		t.Fatal("password should be pwned")
	}
}

func TestHIBPChecker_UnknownPassword(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintln(w, "003D68EB55068C33ACE09247EE4C639306B:3")
	}))
	defer srv.Close()
	c := &HIBPChecker{Endpoint: srv.URL}
	got, err := c.IsPwned(context.Background(), "NoOneUsesThisExactString!@#$%^")
	if err != nil {
		t.Fatalf("IsPwned: %v", err)
	}
	if got {
		t.Fatal("password should NOT be pwned")
	}
}

func TestHIBPChecker_PaddingCountZeroNotPwned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintln(w, "1E4C9B93F3F0682250B6CF8331B7EE68FD8:0")
	}))
	defer srv.Close()
	c := &HIBPChecker{Endpoint: srv.URL}
	got, err := c.IsPwned(context.Background(), "password")
	if err != nil {
		t.Fatalf("IsPwned: %v", err)
	}
	if got {
		t.Fatal("count=0 must not count as pwned (HIBP padding)")
	}
}

func TestHIBPChecker_NilReceiverReturnsFalseNoError(t *testing.T) {
	var c *HIBPChecker
	got, err := c.IsPwned(context.Background(), "anything")
	if err != nil {
		t.Fatalf("nil-receiver should not error: %v", err)
	}
	if got {
		t.Fatal("nil-receiver must always return false")
	}
}

func TestHIBPChecker_HTTPServerError_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := &HIBPChecker{Endpoint: srv.URL}
	got, err := c.IsPwned(context.Background(), "password")
	if err == nil {
		t.Fatal("5xx should return an error (caller fails open)")
	}
	if got {
		t.Fatal("on error IsPwned returns false")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("error should mention status: %v", err)
	}
}

func TestHIBPChecker_CaseInsensitiveSuffix(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintln(w, "1e4c9b93f3f0682250b6cf8331b7ee68fd8:42")
	}))
	defer srv.Close()
	c := &HIBPChecker{Endpoint: srv.URL}
	got, err := c.IsPwned(context.Background(), "password")
	if err != nil {
		t.Fatalf("IsPwned: %v", err)
	}
	if !got {
		t.Fatal("lowercase suffix must match")
	}
}

func TestHIBPChecker_MalformedLinesSkipped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintln(w, "")
		_, _ = fmt.Fprintln(w, ":0")
		_, _ = fmt.Fprintln(w, "NOCOLONLINE")
		_, _ = fmt.Fprintln(w, "1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824")
	}))
	defer srv.Close()
	c := &HIBPChecker{Endpoint: srv.URL}
	got, err := c.IsPwned(context.Background(), "password")
	if err != nil {
		t.Fatalf("IsPwned: %v", err)
	}
	if !got {
		t.Fatal("valid match after malformed lines must be honored")
	}
}

func TestHIBPChecker_EmptyCountNotPwned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintln(w, "1E4C9B93F3F0682250B6CF8331B7EE68FD8:")
	}))
	defer srv.Close()
	c := &HIBPChecker{Endpoint: srv.URL}
	got, err := c.IsPwned(context.Background(), "password")
	if err != nil {
		t.Fatalf("IsPwned: %v", err)
	}
	if got {
		t.Fatal("empty count must not count as pwned")
	}
}

func TestHIBPChecker_ContextCancel_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(500 * time.Millisecond)
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	c := &HIBPChecker{Endpoint: srv.URL}
	_, err := c.IsPwned(ctx, "password")
	if err == nil {
		t.Fatal("expected error on context deadline")
	}
}
