package oidc

import "strings"

// DiscoveryMetadata is the structure served at /.well-known/openid-configuration.
// Field tags follow the OIDC Core 1.0 discovery names exactly.
type DiscoveryMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserInfoEndpoint                  string   `json:"userinfo_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
}

// BuildDiscoveryMetadata returns the Ship-B capability advertisement. Any
// trailing slash on issuer is stripped so endpoint URLs are not double-slashed.
func BuildDiscoveryMetadata(issuer string) DiscoveryMetadata {
	iss := strings.TrimRight(issuer, "/")
	return DiscoveryMetadata{
		Issuer:                            iss,
		AuthorizationEndpoint:             iss + "/authorize",
		TokenEndpoint:                     iss + "/token",
		UserInfoEndpoint:                  iss + "/userinfo",
		JWKSURI:                           iss + "/.well-known/jwks.json",
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		ScopesSupported:                   []string{"openid", "profile", "email", "offline_access"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post"},
		ClaimsSupported: []string{
			"sub", "iss", "aud", "iat", "exp", "nbf", "jti", "auth_time", "nonce",
			"scope", "preferred_username", "updated_at", "email", "email_verified",
		},
		CodeChallengeMethodsSupported: []string{"S256"},
	}
}
