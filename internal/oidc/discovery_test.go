package oidc

import "testing"

func TestBuildDiscoveryMetadata(t *testing.T) {
	d := BuildDiscoveryMetadata("https://id.example.com")
	if d.Issuer != "https://id.example.com" {
		t.Fatalf("issuer=%s", d.Issuer)
	}
	if d.AuthorizationEndpoint != "https://id.example.com/authorize" {
		t.Fatalf("auth_ep=%s", d.AuthorizationEndpoint)
	}
	if d.TokenEndpoint != "https://id.example.com/token" {
		t.Fatalf("token_ep=%s", d.TokenEndpoint)
	}
	if d.UserInfoEndpoint != "https://id.example.com/userinfo" {
		t.Fatalf("userinfo_ep=%s", d.UserInfoEndpoint)
	}
	if d.JWKSURI != "https://id.example.com/.well-known/jwks.json" {
		t.Fatalf("jwks=%s", d.JWKSURI)
	}
	assertHas := func(slice []string, want string) {
		t.Helper()
		for _, v := range slice {
			if v == want {
				return
			}
		}
		t.Fatalf("missing %q in %v", want, slice)
	}
	assertHas(d.ResponseTypesSupported, "code")
	assertHas(d.GrantTypesSupported, "authorization_code")
	assertHas(d.GrantTypesSupported, "refresh_token")
	assertHas(d.SubjectTypesSupported, "public")
	assertHas(d.IDTokenSigningAlgValuesSupported, "RS256")
	assertHas(d.ScopesSupported, "openid")
	assertHas(d.ScopesSupported, "profile")
	assertHas(d.ScopesSupported, "email")
	assertHas(d.ScopesSupported, "offline_access")
	assertHas(d.TokenEndpointAuthMethodsSupported, "client_secret_post")
	assertHas(d.CodeChallengeMethodsSupported, "S256")
}

func TestBuildDiscoveryMetadata_StripsTrailingSlash(t *testing.T) {
	d := BuildDiscoveryMetadata("https://id.example.com/")
	if d.AuthorizationEndpoint != "https://id.example.com/authorize" {
		t.Fatalf("auth_ep=%s (trailing slash not handled)", d.AuthorizationEndpoint)
	}
	if d.Issuer != "https://id.example.com" {
		t.Fatalf("issuer=%s (trailing slash not stripped)", d.Issuer)
	}
}
