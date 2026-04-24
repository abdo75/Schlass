package clients

import "testing"

func TestValidateRedirectURIInput(t *testing.T) {
	cases := []struct {
		name    string
		uri     string
		wantErr bool
	}{
		{"https ok", "https://portal.example.com/cb", false},
		{"http loopback ok", "http://localhost:3000/cb", false},
		{"http 127 ok", "http://127.0.0.1:8080/cb", false},
		{"http ipv6 ok", "http://[::1]/cb", false},
		{"http non-loopback rejected", "http://attacker.com/cb", true},
		{"javascript scheme rejected", "javascript:alert(1)", true},
		{"fragment rejected", "https://x.com/cb#token=leak", true},
		{"wildcard rejected", "https://*.x.com/cb", true},
		{"query ok", "https://x.com/cb?wild=x", false},
		{"spaces rejected", "https:// x.com/cb", true},
		{"empty rejected", "", true},
		{"no scheme rejected", "x.com/cb", true},
	}
	long := "https://x.com/"
	for i := 0; i < 2050; i++ {
		long += "a"
	}
	cases = append(cases, struct {
		name    string
		uri     string
		wantErr bool
	}{"overlong rejected", long, true})

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRedirectURIInput(tc.uri)
			if tc.wantErr && err == nil {
				t.Errorf("ValidateRedirectURIInput(%q): expected error", tc.uri)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("ValidateRedirectURIInput(%q): unexpected err: %v", tc.uri, err)
			}
		})
	}
}
