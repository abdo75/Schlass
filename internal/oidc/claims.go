package oidc

import (
	"strings"
	"time"

	"github.com/abdo75/Schlass/internal/store"
)

const (
	// AccessTokenTTL is the absolute lifetime of an access token per spec §5h.
	AccessTokenTTL = 15 * time.Minute
	// IDTokenTTL matches AccessTokenTTL for Ship B.
	IDTokenTTL = 15 * time.Minute
)

// Scopes wraps a space-separated scope string. Helpers for membership
// and serialization keep scope handling consistent across the claims +
// /token code path.
type Scopes []string

func (s Scopes) String() string { return strings.Join(s, " ") }

func (s Scopes) Has(want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}

// BuildAccessClaims produces the access-token claims body (RFC 9068).
// issuer is SCHLASS_PUBLIC_URL; audience is the client_id (string).
// jti is the caller-generated JWT ID; now is the caller's sign time.
func BuildAccessClaims(
	user *store.User, clientID, issuer, jti string,
	scopes Scopes, now time.Time,
) AccessTokenClaims {
	return AccessTokenClaims{
		Issuer:    issuer,
		Subject:   user.ID.String(),
		Audience:  clientID,
		IssuedAt:  now.Unix(),
		NotBefore: now.Unix(),
		Expires:   now.Add(AccessTokenTTL).Unix(),
		JTI:       jti,
		Scope:     scopes.String(),
	}
}

// BuildIDClaims produces the ID-token claims body (OIDC Core). authTime is
// the session's CreatedAt (see spec §5a.6 — session.CreatedAt IS auth_time).
// nonce is the nonce stored on the authorization_code row (may be empty).
// If scopes include "profile", preferred_username and updated_at are set.
// If scopes include "email", email and email_verified=true are set.
func BuildIDClaims(
	user *store.User, clientID, issuer, jti, nonce string,
	scopes Scopes, authTime time.Time, now time.Time,
) IDTokenClaims {
	c := IDTokenClaims{
		Issuer:    issuer,
		Subject:   user.ID.String(),
		Audience:  clientID,
		IssuedAt:  now.Unix(),
		NotBefore: now.Unix(),
		Expires:   now.Add(IDTokenTTL).Unix(),
		JTI:       jti,
		AuthTime:  authTime.Unix(),
		Nonce:     nonce,
	}
	if scopes.Has("profile") {
		c.PreferredUsername = user.Email
		c.UpdatedAt = user.UpdatedAt.Unix()
	}
	if scopes.Has("email") {
		verified := true
		c.Email = user.Email
		c.EmailVerified = &verified
	}
	return c
}

// UserInfoClaims emits the body of the /userinfo response per token scopes.
// sub is always present. The shape differs from ID-token claims: iss/aud/iat
// are not set (userinfo is not a JWT) — this is a plain JSON object.
type UserInfoClaims struct {
	Sub               string `json:"sub"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	UpdatedAt         int64  `json:"updated_at,omitempty"`
	Email             string `json:"email,omitempty"`
	EmailVerified     *bool  `json:"email_verified,omitempty"`
}

// BuildUserInfoClaims produces the /userinfo body per token scope list.
func BuildUserInfoClaims(user *store.User, scopes Scopes) UserInfoClaims {
	c := UserInfoClaims{Sub: user.ID.String()}
	if scopes.Has("profile") {
		c.PreferredUsername = user.Email
		c.UpdatedAt = user.UpdatedAt.Unix()
	}
	if scopes.Has("email") {
		verified := true
		c.Email = user.Email
		c.EmailVerified = &verified
	}
	return c
}
