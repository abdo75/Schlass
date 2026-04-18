package oidc

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func makeLookup(t *testing.T, expectedKid string, pubPEM []byte) PublicKeyLookup {
	t.Helper()
	return func(kid string) ([]byte, error) {
		if kid != expectedKid {
			t.Fatalf("unexpected kid=%s", kid)
		}
		return pubPEM, nil
	}
}

func TestSignAndVerifyAccessToken_RoundTrip(t *testing.T) {
	pubPEM, privPEM, _ := GenerateKeyPair()
	kid := uuid.NewString()
	claims := AccessTokenClaims{
		Issuer:    "https://id.example.com",
		Subject:   uuid.NewString(),
		Audience:  uuid.NewString(),
		IssuedAt:  time.Now().Unix(),
		NotBefore: time.Now().Unix(),
		Expires:   time.Now().Add(15 * time.Minute).Unix(),
		JTI:       uuid.NewString(),
		Scope:     "openid profile",
	}
	signed, err := SignAccessToken(claims, kid, privPEM)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	parsed, err := ParseAndVerifyAccessToken(signed, makeLookup(t, kid, pubPEM))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if parsed.Subject != claims.Subject {
		t.Fatalf("sub mismatch: got %s want %s", parsed.Subject, claims.Subject)
	}
	if parsed.Scope != claims.Scope {
		t.Fatalf("scope mismatch")
	}
	if parsed.Audience != claims.Audience {
		t.Fatalf("aud mismatch")
	}
}

func TestSignAndVerifyIDToken_RoundTrip(t *testing.T) {
	pubPEM, privPEM, _ := GenerateKeyPair()
	kid := uuid.NewString()
	verified := true
	claims := IDTokenClaims{
		Issuer:            "https://id.example.com",
		Subject:           uuid.NewString(),
		Audience:          uuid.NewString(),
		IssuedAt:          time.Now().Unix(),
		NotBefore:         time.Now().Unix(),
		Expires:           time.Now().Add(15 * time.Minute).Unix(),
		JTI:               uuid.NewString(),
		AuthTime:          time.Now().Unix(),
		Nonce:             "nonce-abc",
		PreferredUsername: "alice@example.com",
		Email:             "alice@example.com",
		EmailVerified:     &verified,
	}
	signed, err := SignIDToken(claims, kid, privPEM)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	parsed, err := ParseAndVerifyIDToken(signed, makeLookup(t, kid, pubPEM))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if parsed.Nonce != "nonce-abc" {
		t.Fatalf("nonce mismatch")
	}
	if parsed.PreferredUsername != "alice@example.com" {
		t.Fatalf("preferred_username mismatch")
	}
	if parsed.EmailVerified == nil || !*parsed.EmailVerified {
		t.Fatalf("email_verified mismatch")
	}
}

func TestVerify_RejectsAlgNone(t *testing.T) {
	pubPEM, _, _ := GenerateKeyPair()
	tok := jwtlib.NewWithClaims(jwtlib.SigningMethodNone, jwtlib.MapClaims{"sub": "x"})
	tok.Header["typ"] = "at+jwt"
	tok.Header["kid"] = "anything"
	signed, _ := tok.SignedString(jwtlib.UnsafeAllowNoneSignatureType)
	_, err := ParseAndVerifyAccessToken(signed, makeLookup(t, "anything", pubPEM))
	if err == nil {
		t.Fatal("alg=none must be rejected")
	}
	if !strings.Contains(err.Error(), "unexpected signing method") {
		t.Fatalf("error should mention signing method, got: %v", err)
	}
}

func TestVerify_RejectsHS256ViaAlgConfusion(t *testing.T) {
	pubPEM, _, _ := GenerateKeyPair()
	tok := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, jwtlib.MapClaims{"sub": "x"})
	tok.Header["typ"] = "at+jwt"
	tok.Header["kid"] = "k"
	signed, _ := tok.SignedString(pubPEM)
	_, err := ParseAndVerifyAccessToken(signed, makeLookup(t, "k", pubPEM))
	if err == nil {
		t.Fatal("HS256 must be rejected (alg confusion defense)")
	}
}

func TestVerify_RejectsWrongTyp(t *testing.T) {
	pubPEM, privPEM, _ := GenerateKeyPair()
	kid := "k"
	// Sign as an ID token (typ=JWT) but try to verify as an access token (typ=at+jwt).
	signed, _ := SignIDToken(IDTokenClaims{
		Issuer:   "a",
		Subject:  "s",
		Audience: "a",
		IssuedAt: time.Now().Unix(),
		Expires:  time.Now().Add(time.Minute).Unix(),
		JTI:      "j",
	}, kid, privPEM)
	_, err := ParseAndVerifyAccessToken(signed, makeLookup(t, kid, pubPEM))
	if err == nil {
		t.Fatal("typ=JWT should be rejected when expecting at+jwt")
	}
}

func TestVerify_RejectsMissingKid(t *testing.T) {
	pubPEM, privPEM, _ := GenerateKeyPair()
	priv, _ := ParsePrivatePEM(privPEM)
	tok := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, jwtlib.MapClaims{"sub": "x"})
	tok.Header["typ"] = "at+jwt"
	// Deliberately NOT setting kid.
	delete(tok.Header, "kid")
	signed, _ := tok.SignedString(priv)
	_, err := ParseAndVerifyAccessToken(signed, func(kid string) ([]byte, error) {
		return pubPEM, nil
	})
	if err == nil {
		t.Fatal("missing kid must be rejected")
	}
}

func TestHeaders_EmitCorrectTypAndKid(t *testing.T) {
	_, privPEM, _ := GenerateKeyPair()
	signed, _ := SignAccessToken(AccessTokenClaims{Issuer: "a", Subject: "s", Audience: "a", IssuedAt: 1, Expires: 2}, "my-kid", privPEM)
	parts := strings.Split(signed, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWT: %s", signed)
	}
	headerJSON, _ := base64.RawURLEncoding.DecodeString(parts[0])
	if !strings.Contains(string(headerJSON), `"typ":"at+jwt"`) {
		t.Fatalf("access token header missing typ=at+jwt: %s", headerJSON)
	}
	if !strings.Contains(string(headerJSON), `"kid":"my-kid"`) {
		t.Fatalf("access token header missing kid: %s", headerJSON)
	}

	signed2, _ := SignIDToken(IDTokenClaims{Issuer: "a", Subject: "s", Audience: "a", IssuedAt: 1, Expires: 2}, "id-kid", privPEM)
	parts2 := strings.Split(signed2, ".")
	headerJSON2, _ := base64.RawURLEncoding.DecodeString(parts2[0])
	if !strings.Contains(string(headerJSON2), `"typ":"JWT"`) {
		t.Fatalf("id token header missing typ=JWT: %s", headerJSON2)
	}
}
