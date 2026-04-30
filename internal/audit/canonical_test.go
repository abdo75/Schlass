package audit

import (
	"testing"
)

// TestCanonicalize_EmptyObject is the simplest RFC 8785 §3.2 vector.
func TestCanonicalize_EmptyObject(t *testing.T) {
	got, err := Canonicalize(map[string]any{})
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	want := `{}`
	if string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// TestCanonicalize_SortedKeys exercises the UTF-16 code-unit ordering of
// object keys (RFC 8785 §3.2.3). The pair "a" / "Z" sorts as Z < a in
// codepoint order — different from English alphabetical.
func TestCanonicalize_SortedKeys(t *testing.T) {
	got, err := Canonicalize(map[string]any{"a": 1, "Z": 2, "b": 3})
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	want := `{"Z":2,"a":1,"b":3}`
	if string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// TestCanonicalize_NestedSorted asserts sorting recurses into nested
// objects.
func TestCanonicalize_NestedSorted(t *testing.T) {
	in := map[string]any{
		"outer": map[string]any{
			"z": 1,
			"a": 2,
		},
	}
	got, err := Canonicalize(in)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	want := `{"outer":{"a":2,"z":1}}`
	if string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// TestCanonicalize_NumbersIntegerForm asserts whole numbers render
// without a trailing `.0`. The JSON decoder reads "1" as json.Number;
// our number formatter keeps the integer form.
func TestCanonicalize_NumbersIntegerForm(t *testing.T) {
	got, err := Canonicalize(map[string]any{"n": 1})
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	want := `{"n":1}`
	if string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// TestCanonicalize_NumbersFloat asserts floats use the shortest
// round-trip form. Go's strconv.FormatFloat 'g' / -1 matches ECMAScript
// for double-precision values, which is what RFC 8785 §3.2.4
// references.
func TestCanonicalize_NumbersFloat(t *testing.T) {
	got, err := Canonicalize(map[string]any{"x": 1.5})
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	want := `{"x":1.5}`
	if string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// TestCanonicalize_NumberFloatExponentCollapsed asserts a value that
// would otherwise be exponentially formatted (1e0 == 1) collapses to
// the integer form. ECMAScript Number toString for the value 1.0 is
// "1", not "1e0".
func TestCanonicalize_NumberFloatExponentCollapsed(t *testing.T) {
	got, err := Canonicalize(map[string]any{"x": 1e0})
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	want := `{"x":1}`
	if string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// TestCanonicalize_StringEscaping checks the JCS-mandated short escape
// forms for control characters.
func TestCanonicalize_StringEscaping(t *testing.T) {
	got, err := Canonicalize(map[string]any{"s": "a\tb\nc\"d"})
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	want := `{"s":"a\tb\nc\"d"}`
	if string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// TestCanonicalize_NFCNormalisation verifies NFD-decomposed input ("e"
// + U+0301 combining acute) emits the NFC composed form ("é"). RFC 8785
// §3.2.2 mandates NFC for string values.
func TestCanonicalize_NFCNormalisation(t *testing.T) {
	// "café" with the é in decomposed form.
	in := map[string]any{"name": "café"}
	got, err := Canonicalize(in)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	want := "{\"name\":\"café\"}"
	if string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// TestCanonicalize_BoolNullArray covers the remaining JSON value
// shapes.
func TestCanonicalize_BoolNullArray(t *testing.T) {
	got, err := Canonicalize(map[string]any{"a": []any{true, false, nil}})
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	want := `{"a":[true,false,null]}`
	if string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// TestCanonicalize_Determinism re-encodes the same input twice and
// asserts byte-equal output. This is the property chain.go relies on:
// the same row encoded twice MUST produce the same bytes.
func TestCanonicalize_Determinism(t *testing.T) {
	in := map[string]any{
		"event_type":  "login.succeeded",
		"outcome":     "success",
		"actor_id":    "00000000-0000-0000-0000-000000000001",
		"sequence_no": 42,
		"metadata":    map[string]any{"method": "password"},
	}
	a, err := Canonicalize(in)
	if err != nil {
		t.Fatalf("canonicalize 1: %v", err)
	}
	b, err := Canonicalize(in)
	if err != nil {
		t.Fatalf("canonicalize 2: %v", err)
	}
	if string(a) != string(b) {
		t.Fatalf("non-deterministic: %q vs %q", a, b)
	}
}
