package oidc

import (
	"strings"
	"time"

	"github.com/abdo75/Schlass/internal/users"
)

const (
	AccessTokenTTL = 15 * time.Minute
	IDTokenTTL     = 15 * time.Minute
)

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

// BuildAccessClaims: RFC 9068. issuer = SCHLASS_PUBLIC_URL, aud = client_id.
func BuildAccessClaims(
	user *users.User, clientID, issuer, jti string,
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

// BuildIDClaims: authTime = session.CreatedAt (spec §5a.6). Profile scope
// adds preferred_username + updated_at; email scope adds email + verified=true.
func BuildIDClaims(
	user *users.User, clientID, issuer, jti, nonce string,
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

// UserInfoClaims is plain JSON (not a JWT) — OIDC Core §5.3 allows either.
type UserInfoClaims struct {
	Sub               string `json:"sub"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	UpdatedAt         int64  `json:"updated_at,omitempty"`
	Email             string `json:"email,omitempty"`
	EmailVerified     *bool  `json:"email_verified,omitempty"`
}

func BuildUserInfoClaims(user *users.User, scopes Scopes) UserInfoClaims {
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
