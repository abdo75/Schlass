package model

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
