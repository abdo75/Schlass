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

// ErrClientNotFound collapses unknown + disabled — disabled clients must be
// indistinguishable from unknown ones at GetByID (enumeration defense).
var ErrClientNotFound = errors.New("client: not found")

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

// GetByID: active clients only (used by /authorize and /token). Disabled +
// unknown + bad-UUID all collapse to ErrClientNotFound.
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

// GetByIDAny: admin path — returns client regardless of status.
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

// GetByIDForUpdate serializes concurrent PATCHes on the same client.
// Must be called inside a tx.
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

// VerifySecret tries current, then previous (if overlap window open). The
// ~30ms Argon2id cost difference between current-match and previous-match
// is accepted as timing side-channel — consistent with Sprint 2 enumeration
// precedent. Only info leaked is "rotation happened recently", which the
// attacker infers from possessing the old secret anyway.
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

// List — status: "active" | "disabled" | "all". Ordered by created_at DESC.
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

// ValidateRedirectURI: exact-string match, case- and scheme-sensitive, no
// wildcards.
func (s *ClientStore) ValidateRedirectURI(c *Client, presented string) bool {
	for _, r := range c.RedirectURIs {
		if r == presented {
			return true
		}
	}
	return false
}

// CreateClientParams.SecretHash must already be Argon2id-hashed.
type CreateClientParams struct {
	Name                    string
	ClientType              string
	SecretHash              string
	RedirectURIs            []string
	AllowedGrantTypes       []string
	AllowedScopes           []string
	TokenEndpointAuthMethod string
	CreatedByUserID         *uuid.UUID
}

func (s *ClientStore) Create(ctx context.Context, q database.Querier, p CreateClientParams) (*Client, error) {
	row := q.QueryRow(ctx, `
		INSERT INTO clients (
			name, client_type, secret_hash, redirect_uris,
			allowed_grant_types, allowed_scopes, token_endpoint_auth_method,
			created_by_user_id
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING `+clientSelectColumns,
		p.Name, p.ClientType, p.SecretHash, p.RedirectURIs,
		p.AllowedGrantTypes, p.AllowedScopes, p.TokenEndpointAuthMethod,
		p.CreatedByUserID,
	)
	c, err := scanClient(row)
	if err != nil {
		return nil, fmt.Errorf("client create: %w", err)
	}
	return c, nil
}

// UpdateClientPatch — nil fields not updated.
type UpdateClientPatch struct {
	Name              *string
	RedirectURIs      *[]string
	AllowedScopes     *[]string
	AllowedGrantTypes *[]string
}

// UpdateFields — COALESCE keeps SQL flat; nil args = no change.
// updated_at bumped on every call.
func (s *ClientStore) UpdateFields(ctx context.Context, q database.Querier, id string, p UpdateClientPatch) (*Client, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, ErrClientNotFound
	}
	row := q.QueryRow(ctx, `
		UPDATE clients SET
			name                = COALESCE($2, name),
			redirect_uris       = COALESCE($3, redirect_uris),
			allowed_scopes      = COALESCE($4, allowed_scopes),
			allowed_grant_types = COALESCE($5, allowed_grant_types),
			updated_at          = now()
		WHERE id = $1
		RETURNING `+clientSelectColumns,
		uid, p.Name, p.RedirectURIs, p.AllowedScopes, p.AllowedGrantTypes,
	)
	c, err := scanClient(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrClientNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("client update: %w", err)
	}
	return c, nil
}

// RotateSecret: current → previous slot with TTL, newHash → current. Any
// existing previous is discarded.
func (s *ClientStore) RotateSecret(ctx context.Context, q database.Querier, id, newHash string, overlapTTL time.Duration) (*Client, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, ErrClientNotFound
	}
	expiresAt := time.Now().UTC().Add(overlapTTL)
	row := q.QueryRow(ctx, `
		UPDATE clients SET
			secret_hash_previous        = secret_hash,
			secret_previous_expires_at  = $3,
			secret_hash                 = $2,
			updated_at                  = now()
		WHERE id = $1
		RETURNING `+clientSelectColumns,
		uid, newHash, expiresAt,
	)
	c, err := scanClient(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrClientNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("client rotate: %w", err)
	}
	return c, nil
}

// Disable: ErrClientNotFound if unknown or already disabled.
func (s *ClientStore) Disable(ctx context.Context, q database.Querier, id string) error {
	uid, err := uuid.Parse(id)
	if err != nil {
		return ErrClientNotFound
	}
	ct, err := q.Exec(ctx, `
		UPDATE clients
		SET status = 'disabled', disabled_at = now(), updated_at = now()
		WHERE id = $1 AND status = 'active'
	`, uid)
	if err != nil {
		return fmt.Errorf("client disable: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrClientNotFound
	}
	return nil
}

// Enable: ErrClientNotFound if unknown or already active.
func (s *ClientStore) Enable(ctx context.Context, q database.Querier, id string) error {
	uid, err := uuid.Parse(id)
	if err != nil {
		return ErrClientNotFound
	}
	ct, err := q.Exec(ctx, `
		UPDATE clients
		SET status = 'active', disabled_at = NULL, updated_at = now()
		WHERE id = $1 AND status = 'disabled'
	`, uid)
	if err != nil {
		return fmt.Errorf("client enable: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrClientNotFound
	}
	return nil
}

// Delete hard-removes. Auth codes cascade via FK (migration 000017).
// Caller post-commits revokebefore.ClientSetNow for outstanding refresh tokens.
func (s *ClientStore) Delete(ctx context.Context, q database.Querier, id string) error {
	uid, err := uuid.Parse(id)
	if err != nil {
		return ErrClientNotFound
	}
	ct, err := q.Exec(ctx, `DELETE FROM clients WHERE id = $1`, uid)
	if err != nil {
		return fmt.Errorf("client delete: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrClientNotFound
	}
	return nil
}
