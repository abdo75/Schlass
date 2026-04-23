package authserver

import "testing"

func TestIntersectScopesAgainstClient(t *testing.T) {
	cases := []struct {
		name    string
		granted []string
		allowed []string
		want    []string
		wantErr bool
	}{
		{"full overlap", []string{"openid", "profile"}, []string{"openid", "profile", "email"}, []string{"openid", "profile"}, false},
		{"partial overlap narrows", []string{"openid", "profile", "email"}, []string{"openid", "email"}, []string{"openid", "email"}, false},
		{"empty intersection rejects", []string{"profile"}, []string{"openid"}, nil, true},
		{"both empty rejects", []string{}, []string{}, nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := intersectScopesAgainstClient(tc.granted, tc.allowed)
			if tc.wantErr {
				if err == nil {
					t.Errorf("want error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
				return
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("got[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}
