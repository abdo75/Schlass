package oidc

import (
	"strings"
	"testing"
)

func TestNewCorrelationID(t *testing.T) {
	a, err := NewCorrelationID()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewCorrelationID()
	if a == b {
		t.Fatal("correlation IDs must be unique")
	}
	if !strings.HasPrefix(a, "err_") {
		t.Fatalf("prefix: %s", a)
	}
	// err_ + 32 hex chars
	if len(a) != len("err_")+32 {
		t.Fatalf("len=%d want %d", len(a), len("err_")+32)
	}
}
