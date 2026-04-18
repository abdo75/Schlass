package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/abdo75/Schlass/internal/crypto"
	"github.com/abdo75/Schlass/internal/database"
)

// Client mirrors the clients row for Ship B's read path. Sprint 5 grows this
// with CreatedAt/UpdatedAt shaped DTOs; Ship B only needs what the OIDC
// handlers consume.
type Client struct {
	ID                      uuid.UUID
	Name                    string
	ClientType              string
	SecretHash              *string
	RedirectURIs            []string
	AllowedGrantTypes       []string
	AllowedScopes           []string
	TokenEndpointAuthMethod string
	Status                  string
}

// ErrClientNotFound is returned by GetByID on unknown OR disabled clients —
// disabled clients must be indistinguishable from unknown ones to callers
// (enumeration defense).
var ErrClientNotFound = errors.New("client: not found")

// ClientStore holds no state; it is a method namespace for client SQL operations.
type ClientStore struct{}

func NewClientStore() *ClientStore { return &ClientStore{} }

// GetByID loads an active client by its UUID. Returns ErrClientNotFound
// for disabled, unknown, or malformed-UUID inputs.
func (s *ClientStore) GetByID(ctx context.Context, q database.Querier, id string) (*Client, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, ErrClientNotFound
	}
	var c Client
	err = q.QueryRow(ctx, `
		SELECT id, name, client_type, secret_hash, redirect_uris,
		       allowed_grant_types, allowed_scopes, token_endpoint_auth_method, status
		FROM clients
		WHERE id = $1 AND status = 'active'
	`, uid).Scan(&c.ID, &c.Name, &c.ClientType, &c.SecretHash,
		&c.RedirectURIs, &c.AllowedGrantTypes, &c.AllowedScopes,
		&c.TokenEndpointAuthMethod, &c.Status)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrClientNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("client get: %w", err)
	}
	return &c, nil
}

// VerifySecret checks a provided plaintext secret against the stored Argon2id
// hash. Constant-time via Argon2id verify.
func (s *ClientStore) VerifySecret(ctx context.Context, q database.Querier, id, secret string) (bool, error) {
	c, err := s.GetByID(ctx, q, id)
	if err != nil {
		return false, err
	}
	if c.SecretHash == nil {
		return false, nil
	}
	return crypto.VerifyPassword(secret, *c.SecretHash)
}

// ValidateRedirectURI does an exact-string match against registered URIs.
// Case-sensitive, scheme-sensitive, no wildcards.
func (s *ClientStore) ValidateRedirectURI(c *Client, presented string) bool {
	for _, r := range c.RedirectURIs {
		if r == presented {
			return true
		}
	}
	return false
}
