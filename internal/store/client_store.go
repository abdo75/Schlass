package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/abdo75/Schlass/internal/crypto"
	"github.com/abdo75/Schlass/internal/database"
)

// Client mirrors the clients row, including the Sprint 5 metadata columns.
type Client struct {
	ID                      uuid.UUID
	Name                    string
	ClientType              string
	SecretHash              *string
	SecretHashPrevious      *string
	SecretPreviousExpiresAt *time.Time
	RedirectURIs            []string
	AllowedGrantTypes       []string
	AllowedScopes           []string
	TokenEndpointAuthMethod string
	Status                  string
	DisabledAt              *time.Time
	CreatedByUserID         *uuid.UUID
	CreatedAt               time.Time
	UpdatedAt               time.Time
}

// ErrClientNotFound is returned by GetByID on unknown OR disabled clients —
// disabled clients must be indistinguishable from unknown ones to callers
// (enumeration defense).
var ErrClientNotFound = errors.New("client: not found")

// ClientStore holds no state; it is a method namespace for client SQL operations.
type ClientStore struct{}

func NewClientStore() *ClientStore { return &ClientStore{} }

const clientSelectColumns = `
	id, name, client_type, secret_hash, secret_hash_previous, secret_previous_expires_at,
	redirect_uris, allowed_grant_types, allowed_scopes, token_endpoint_auth_method,
	status, disabled_at, created_by_user_id, created_at, updated_at
`

func scanClient(row pgx.Row) (*Client, error) {
	var c Client
	err := row.Scan(&c.ID, &c.Name, &c.ClientType, &c.SecretHash,
		&c.SecretHashPrevious, &c.SecretPreviousExpiresAt,
		&c.RedirectURIs, &c.AllowedGrantTypes, &c.AllowedScopes,
		&c.TokenEndpointAuthMethod, &c.Status, &c.DisabledAt, &c.CreatedByUserID,
		&c.CreatedAt, &c.UpdatedAt)
	return &c, err
}

// GetByID — OIDC-safe: active clients only. Used by /authorize and /token.
// Returns ErrClientNotFound for disabled, unknown, or malformed-UUID inputs
// (enumeration defense).
func (s *ClientStore) GetByID(ctx context.Context, q database.Querier, id string) (*Client, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, ErrClientNotFound
	}
	row := q.QueryRow(ctx, `SELECT `+clientSelectColumns+` FROM clients WHERE id = $1 AND status = 'active'`, uid)
	c, err := scanClient(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrClientNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("client get: %w", err)
	}
	return c, nil
}

// GetByIDAny — admin: returns client regardless of status. Used by the admin
// /api/clients/:id endpoint which must surface disabled clients.
func (s *ClientStore) GetByIDAny(ctx context.Context, q database.Querier, id string) (*Client, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, ErrClientNotFound
	}
	row := q.QueryRow(ctx, `SELECT `+clientSelectColumns+` FROM clients WHERE id = $1`, uid)
	c, err := scanClient(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrClientNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("client get: %w", err)
	}
	return c, nil
}

// GetByIDForUpdate — admin: returns client under a row lock. Serializes
// concurrent PATCHes on the same client. Must be called inside a tx.
func (s *ClientStore) GetByIDForUpdate(ctx context.Context, q database.Querier, id string) (*Client, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, ErrClientNotFound
	}
	row := q.QueryRow(ctx, `SELECT `+clientSelectColumns+` FROM clients WHERE id = $1 FOR UPDATE`, uid)
	c, err := scanClient(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrClientNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("client get-for-update: %w", err)
	}
	return c, nil
}

// VerifySecret returns true if the plaintext matches the current secret OR
// the previous secret while the overlap window is still open. The ~30ms
// Argon2id cost difference between current-match (1 op) and previous-match
// (2 ops) is an accepted timing side-channel — consistent with the Sprint 2
// enumeration-timing precedent documented in CLAUDE.md. The only information
// leaked is "rotation happened recently", which the attacker already infers
// from possessing the old secret.
func (s *ClientStore) VerifySecret(ctx context.Context, q database.Querier, id, secret string) (bool, error) {
	c, err := s.GetByID(ctx, q, id)
	if err != nil {
		return false, err
	}
	if c.SecretHash != nil {
		ok, err := crypto.VerifyPassword(secret, *c.SecretHash)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	if c.SecretHashPrevious != nil && c.SecretPreviousExpiresAt != nil && c.SecretPreviousExpiresAt.After(time.Now().UTC()) {
		ok, err := crypto.VerifyPassword(secret, *c.SecretHashPrevious)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// List returns clients filtered by status. status must be one of
// "active", "disabled", "all". Ordered by created_at DESC.
func (s *ClientStore) List(ctx context.Context, q database.Querier, status string) ([]*Client, error) {
	var rows pgx.Rows
	var err error
	base := `SELECT ` + clientSelectColumns + ` FROM clients `
	switch status {
	case "active":
		rows, err = q.Query(ctx, base+`WHERE status = 'active' ORDER BY created_at DESC`)
	case "disabled":
		rows, err = q.Query(ctx, base+`WHERE status = 'disabled' ORDER BY created_at DESC`)
	case "all":
		rows, err = q.Query(ctx, base+`ORDER BY created_at DESC`)
	default:
		return nil, fmt.Errorf("client list: invalid status filter %q", status)
	}
	if err != nil {
		return nil, fmt.Errorf("client list: %w", err)
	}
	defer rows.Close()

	var out []*Client
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, fmt.Errorf("client list scan: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ValidateRedirectURI — exact-string match, case-sensitive, scheme-sensitive,
// no wildcards.
func (s *ClientStore) ValidateRedirectURI(c *Client, presented string) bool {
	for _, r := range c.RedirectURIs {
		if r == presented {
			return true
		}
	}
	return false
}
