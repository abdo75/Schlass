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
	// "password" SHA-1 = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
	// prefix = 5BAA6, suffix = 1E4C9B93F3F0682250B6CF8331B7EE68FD8
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/5BAA6" {
			t.Errorf("unexpected path %q", r.URL.Path)
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
	// Padding responses include suffix matches with count=0. Must not
	// count as pwned.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// "password" SHA-1 suffix as padding with count=0.
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

