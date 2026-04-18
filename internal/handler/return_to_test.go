package handler

import "testing"

func TestSanitizeReturnTo(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		pub     string
		wantOK  bool
		wantOut string
	}{
		{"empty", "", "https://id.example.com", false, ""},
		{"valid absolute same-origin", "https://id.example.com/authorize?x=1", "https://id.example.com", true, "/authorize?x=1"},
		{"valid relative", "/authorize?x=1", "https://id.example.com", true, "/authorize?x=1"},
		{"valid relative no query", "/authorize", "https://id.example.com", true, "/authorize"},
		{"wrong path", "/admin", "https://id.example.com", false, ""},
		{"wrong host", "https://evil.com/authorize", "https://id.example.com", false, ""},
		{"wrong scheme", "http://id.example.com/authorize", "https://id.example.com", false, ""},
		{"protocol-relative", "//evil.com/authorize", "https://id.example.com", false, ""},
		{"malformed", "http://[::1", "https://id.example.com", false, ""},
		{"trailing path after authorize", "/authorize/extra", "https://id.example.com", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := SanitizeReturnTo(tc.raw, tc.pub)
			if ok != tc.wantOK {
				t.Fatalf("ok=%v want=%v", ok, tc.wantOK)
			}
			if got != tc.wantOut {
				t.Fatalf("got=%q want=%q", got, tc.wantOut)
			}
		})
	}
}
