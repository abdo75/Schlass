package oidc

import (
	"encoding/json"
	"errors"
	"fmt"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

// AccessTokenClaims is the RFC 9068 "at+jwt" claims body for access tokens.
// Field tags use standard JWT registered claim names.
type AccessTokenClaims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	IssuedAt  int64  `json:"iat"`
	NotBefore int64  `json:"nbf"`
	Expires   int64  `json:"exp"`
	JTI       string `json:"jti"`
	Scope     string `json:"scope"`
}

// IDTokenClaims is the OIDC Core §2 ID-token body. Adds OIDC-specific fields
// to the registered-claim fields.
type IDTokenClaims struct {
	Issuer            string `json:"iss"`
	Subject           string `json:"sub"`
	Audience          string `json:"aud"`
	IssuedAt          int64  `json:"iat"`
	NotBefore         int64  `json:"nbf"`
	Expires           int64  `json:"exp"`
	JTI               string `json:"jti"`
	AuthTime          int64  `json:"auth_time,omitempty"`
	Nonce             string `json:"nonce,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	UpdatedAt         int64  `json:"updated_at,omitempty"`
	Email             string `json:"email,omitempty"`
	EmailVerified     *bool  `json:"email_verified,omitempty"`
}

// SignAccessToken returns a signed compact JWT with typ=at+jwt (RFC 9068).
func SignAccessToken(c AccessTokenClaims, kid string, privatePEM []byte) (string, error) {
	return signRS256(c, kid, "at+jwt", privatePEM)
}

// SignIDToken returns a signed compact JWT with typ=JWT (OIDC Core).
func SignIDToken(c IDTokenClaims, kid string, privatePEM []byte) (string, error) {
	return signRS256(c, kid, "JWT", privatePEM)
}

func signRS256(claims any, kid, typ string, privatePEM []byte) (string, error) {
	priv, err := ParsePrivatePEM(privatePEM)
	if err != nil {
		return "", fmt.Errorf("sign: parse private: %w", err)
	}
	m, err := structToMap(claims)
	if err != nil {
		return "", err
	}
	tok := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, jwtlib.MapClaims(m))
	tok.Header["kid"] = kid
	tok.Header["typ"] = typ
	return tok.SignedString(priv)
}

// PublicKeyLookup fetches the public-key PEM bytes for a given kid.
type PublicKeyLookup func(kid string) ([]byte, error)

// ParseAndVerifyAccessToken verifies signature, alg=RS256, and returns parsed
// claims. Does NOT enforce exp/nbf/aud/iss — callers validate those per the
// endpoint's policy.
func ParseAndVerifyAccessToken(raw string, lookup PublicKeyLookup) (*AccessTokenClaims, error) {
	parsed, err := parseAndVerify(raw, lookup, "at+jwt")
	if err != nil {
		return nil, err
	}
	var c AccessTokenClaims
	if err := mapToStruct(parsed, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// ParseAndVerifyIDToken mirrors ParseAndVerifyAccessToken but for ID tokens
// (typ=JWT). Rare server-side use; tests use it to assert emitted claim shape.
func ParseAndVerifyIDToken(raw string, lookup PublicKeyLookup) (*IDTokenClaims, error) {
	parsed, err := parseAndVerify(raw, lookup, "JWT")
	if err != nil {
		return nil, err
	}
	var c IDTokenClaims
	if err := mapToStruct(parsed, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func parseAndVerify(raw string, lookup PublicKeyLookup, wantTyp string) (jwtlib.MapClaims, error) {
	tok, err := jwtlib.Parse(raw,
		func(t *jwtlib.Token) (interface{}, error) {
			// Reject alg != RS256 (defends against alg=none, HS256-confusion).
			if t.Method.Alg() != "RS256" {
				return nil, errors.New("unexpected signing method: " + t.Method.Alg())
			}
			if typ, _ := t.Header["typ"].(string); typ != wantTyp {
				return nil, errors.New("unexpected typ: " + typ)
			}
			kid, _ := t.Header["kid"].(string)
			if kid == "" {
				return nil, errors.New("kid header missing")
			}
			pubPEM, err := lookup(kid)
			if err != nil {
				return nil, err
			}
			return ParsePublicPEM(pubPEM)
		},
		// Disable built-in claims validation — callers handle exp/nbf/iss/aud.
		jwtlib.WithoutClaimsValidation(),
	)
	if err != nil {
		return nil, err
	}
	if !tok.Valid {
		return nil, errors.New("invalid token")
	}
	claims, _ := tok.Claims.(jwtlib.MapClaims)
	return claims, nil
}

func structToMap(v any) (map[string]any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func mapToStruct(m jwtlib.MapClaims, out any) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}
