package oidc

import (
	"testing"
	"time"

	"github.com/abdo75/Schlass/internal/users"
	"github.com/google/uuid"
)

func makeUser() *users.User {
	return &users.User{
		ID:        uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		Email:     "alice@example.com",
		UpdatedAt: time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC),
	}
}

func TestScopes_HasAndString(t *testing.T) {
	s := Scopes{"openid", "profile", "email"}
	if !s.Has("profile") {
		t.Fatal("should have profile")
	}
	if s.Has("offline_access") {
		t.Fatal("should not have offline_access")
	}
	if s.String() != "openid profile email" {
		t.Fatalf("String()=%q", s.String())
	}
}

func TestBuildAccessClaims(t *testing.T) {
	u := makeUser()
	now := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	ttl := 17 * time.Minute
	c := BuildAccessClaims(u, "client-x", "https://id.example.com", "jti-1",
		Scopes{"openid", "profile"}, now, ttl)
	if c.Subject != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("sub=%s", c.Subject)
	}
	if c.Issuer != "https://id.example.com" {
		t.Fatalf("iss=%s", c.Issuer)
	}
	if c.Audience != "client-x" {
		t.Fatalf("aud=%s", c.Audience)
	}
	if c.Scope != "openid profile" {
		t.Fatalf("scope=%q", c.Scope)
	}
	if c.Expires-c.IssuedAt != int64(ttl.Seconds()) {
		t.Fatalf("ttl mismatch: %d", c.Expires-c.IssuedAt)
	}
}

func TestBuildIDClaims_AllScopes(t *testing.T) {
	u := makeUser()
	now := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	auth := now.Add(-30 * time.Second)
	ttl := 23 * time.Minute
	c := BuildIDClaims(u, "client-x", "https://id.example.com", "jti-2", "nonce-xyz",
		Scopes{"openid", "profile", "email"}, auth, now, ttl)
	if c.Nonce != "nonce-xyz" {
		t.Fatalf("nonce=%s", c.Nonce)
	}
	if c.PreferredUsername != "alice@example.com" {
		t.Fatalf("preferred_username=%s", c.PreferredUsername)
	}
	if c.UpdatedAt == 0 {
		t.Fatalf("updated_at unset")
	}
	if c.Email != "alice@example.com" {
		t.Fatalf("email=%s", c.Email)
	}
	if c.EmailVerified == nil || !*c.EmailVerified {
		t.Fatalf("email_verified not true")
	}
	if c.AuthTime != auth.Unix() {
		t.Fatalf("auth_time mismatch")
	}
	if c.Expires-c.IssuedAt != int64(ttl.Seconds()) {
		t.Fatalf("ttl mismatch: %d", c.Expires-c.IssuedAt)
	}
}

func TestBuildIDClaims_OpenIDOnly_OmitsProfileAndEmail(t *testing.T) {
	u := makeUser()
	now := time.Now().UTC()
	c := BuildIDClaims(u, "cid", "iss", "jti", "", Scopes{"openid"}, now, now, 15*time.Minute)
	if c.PreferredUsername != "" {
		t.Fatalf("preferred_username should be empty for openid-only")
	}
	if c.Email != "" {
		t.Fatalf("email should be empty for openid-only")
	}
	if c.EmailVerified != nil {
		t.Fatalf("email_verified should be nil for openid-only")
	}
}

func TestBuildIDClaims_ProfileOnly(t *testing.T) {
	u := makeUser()
	now := time.Now().UTC()
	c := BuildIDClaims(u, "cid", "iss", "jti", "", Scopes{"openid", "profile"}, now, now, 15*time.Minute)
	if c.PreferredUsername != "alice@example.com" {
		t.Fatalf("preferred_username missing")
	}
	if c.Email != "" {
		t.Fatalf("email should be empty for profile-only")
	}
}

func TestBuildIDClaims_EmailOnly(t *testing.T) {
	u := makeUser()
	now := time.Now().UTC()
	c := BuildIDClaims(u, "cid", "iss", "jti", "", Scopes{"openid", "email"}, now, now, 15*time.Minute)
	if c.PreferredUsername != "" {
		t.Fatalf("preferred_username should be empty for email-only")
	}
	if c.Email != "alice@example.com" {
		t.Fatalf("email missing")
	}
}

func TestBuildUserInfoClaims(t *testing.T) {
	u := makeUser()
	c := BuildUserInfoClaims(u, Scopes{"openid", "profile", "email"})
	if c.Sub != "11111111-1111-1111-1111-111111111111" {
		t.Fatal("sub missing")
	}
	if c.PreferredUsername != "alice@example.com" {
		t.Fatal("profile claim missing")
	}
	if c.Email != "alice@example.com" {
		t.Fatal("email claim missing")
	}
	if c.EmailVerified == nil || !*c.EmailVerified {
		t.Fatal("email_verified missing")
	}

	minimal := BuildUserInfoClaims(u, Scopes{"openid"})
	if minimal.PreferredUsername != "" || minimal.Email != "" || minimal.EmailVerified != nil {
		t.Fatalf("openid-only should only emit sub: %+v", minimal)
	}
}
