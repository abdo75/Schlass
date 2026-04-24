package clients

import "testing"

func TestValidateClientName(t *testing.T) {
	cases := []struct {
		in      string
		wantOut string
		wantErr bool
	}{
		{"customer-portal", "customer-portal", false},
		{"  spaced  ", "spaced", false},
		{"", "", true},
		{"   ", "", true},
	}
	longName := ""
	for i := 0; i < 101; i++ {
		longName += "a"
	}
	cases = append(cases, struct {
		in      string
		wantOut string
		wantErr bool
	}{longName, "", true})

	for _, tc := range cases {
		out, err := ValidateClientName(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ValidateClientName(%q) = %q, want error", tc.in, out)
			}
			continue
		}
		if err != nil {
			t.Errorf("ValidateClientName(%q) unexpected err: %v", tc.in, err)
			continue
		}
		if out != tc.wantOut {
			t.Errorf("ValidateClientName(%q) = %q, want %q", tc.in, out, tc.wantOut)
		}
	}
}

func TestValidateScopes(t *testing.T) {
	cases := []struct {
		name    string
		in      []string
		wantErr bool
	}{
		{"empty ok", []string{}, false},
		{"all known", []string{"openid", "profile", "email", "offline_access"}, false},
		{"unknown rejected", []string{"openid", "admin"}, true},
		{"empty string rejected", []string{""}, true},
		{"duplicate rejected", []string{"openid", "openid"}, true},
	}
	for _, tc := range cases {
		err := ValidateScopes(tc.in)
		if tc.wantErr && err == nil {
			t.Errorf("ValidateScopes(%v): expected error", tc.in)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("ValidateScopes(%v): unexpected err: %v", tc.in, err)
		}
	}
}

func TestValidateGrantTypes(t *testing.T) {
	cases := []struct {
		name    string
		in      []string
		wantErr bool
	}{
		{"authorization_code only", []string{"authorization_code"}, false},
		{"both", []string{"authorization_code", "refresh_token"}, false},
		{"empty rejected", []string{}, true},
		{"unknown rejected", []string{"client_credentials"}, true},
		{"duplicate rejected", []string{"authorization_code", "authorization_code"}, true},
	}
	for _, tc := range cases {
		err := ValidateGrantTypes(tc.in)
		if tc.wantErr && err == nil {
			t.Errorf("ValidateGrantTypes(%v): expected error", tc.in)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("ValidateGrantTypes(%v): unexpected err: %v", tc.in, err)
		}
	}
}
