// Unit tests for ParseUAFamily — empty-input contract, the common
// browser shapes, and the bounded-output guarantees that protect
// client_ua_family from attacker-controlled bytes (REQ-AUD-031).
package audit

import (
	"strings"
	"testing"
)

func TestParseUAFamily_Empty(t *testing.T) {
	if got := ParseUAFamily(""); got != "" {
		t.Errorf("empty input: got %q, want empty", got)
	}
	if got := ParseUAFamily("   "); got != "" {
		t.Errorf("whitespace-only input: got %q, want empty", got)
	}
}

func TestParseUAFamily_RealBrowsers(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		// We don't pin exact Family/Major output (depends on the
		// upstream library's parse table), but every real UA must
		// produce a non-empty, allowlist-clean, bounded result.
		wantNonEmpty bool
	}{
		{
			name:         "chrome desktop",
			raw:          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
			wantNonEmpty: true,
		},
		{
			name:         "firefox desktop",
			raw:          "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
			wantNonEmpty: true,
		},
		{
			name:         "safari ios",
			raw:          "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
			wantNonEmpty: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseUAFamily(tc.raw)
			if tc.wantNonEmpty && got == "" {
				t.Fatalf("got empty, want non-empty result for %q", tc.raw)
			}
			if len(got) > uaFamilyMaxLen {
				t.Fatalf("got %q (%d bytes), exceeds cap %d", got, len(got), uaFamilyMaxLen)
			}
			if got != "" && !isAllowedUAFamily(got) {
				t.Fatalf("got %q, contains characters outside the allowlist", got)
			}
		})
	}
}

func TestParseUAFamily_OversizedRejected(t *testing.T) {
	// Pad the Name-bearing section with ASCII letters until the
	// would-be parsed Family blows past the cap. We can't directly
	// craft a Family longer than 32, since the library's parse table
	// is deterministic, but we *can* feed a UA whose tokens are
	// long enough that any path through the parser either rejects
	// (returns "") or returns a clean bounded string. We accept both.
	huge := "Mozilla/5.0 (compatible; " + strings.Repeat("X", 256) + "Bot/9876543210) extra"
	got := ParseUAFamily(huge)
	if len(got) > uaFamilyMaxLen {
		t.Fatalf("oversized UA produced %q (%d bytes), exceeds cap %d", got, len(got), uaFamilyMaxLen)
	}
	if got != "" && !isAllowedUAFamily(got) {
		t.Fatalf("oversized UA produced %q with disallowed bytes", got)
	}
}

func TestParseUAFamily_ControlBytesRejected(t *testing.T) {
	// A UA with raw control bytes / non-ASCII smuggled into a token
	// that ends up surfacing in the parsed Name must NOT round-trip
	// to client_ua_family. Either the library refuses to parse it
	// into a Name (output == "") or our allowlist drops it.
	cases := []string{
		"Mozilla/5.0 \x00\x01\x07Bad/1.0",
		"EvilBrowser\x1b[31m/9.9",
		"\xc3\x28Browser/1.0",         // invalid UTF-8 prefix
		"Browser\nNewline/1.0",        // embedded newline
		"Browser; rm -rf /\nx/1.0",    // shell metachars
		"漢字Browser/1.0",             // non-ASCII Family
	}
	for _, raw := range cases {
		got := ParseUAFamily(raw)
		if got == "" {
			continue
		}
		if len(got) > uaFamilyMaxLen {
			t.Errorf("input %q -> %q exceeds cap", raw, got)
		}
		if !isAllowedUAFamily(got) {
			t.Errorf("input %q -> %q passed but contains disallowed bytes", raw, got)
		}
	}
}

func TestIsAllowedUAFamily(t *testing.T) {
	good := []string{
		"Firefox/126",
		"Chrome",
		"OkHttp 4.12",
		"Mobile_Safari/17",
		"PRE-RELEASE/1",
		"",
	}
	for _, s := range good {
		if !isAllowedUAFamily(s) {
			t.Errorf("expected %q to be allowed", s)
		}
	}
	bad := []string{
		"Firefox\n126",
		"Chrome\x00",
		"Brave;rm",
		"日本語",
		"weird*char",
		"a@b",
	}
	for _, s := range bad {
		if isAllowedUAFamily(s) {
			t.Errorf("expected %q to be rejected", s)
		}
	}
}
