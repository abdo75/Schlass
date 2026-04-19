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

// CreateClientParams is the insert payload. SecretHash must be an Argon2id
// hash; the caller is responsible for hashing before calling.
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

// Create inserts a new client row and returns the full record.
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

// UpdateClientPatch is a partial patch. Nil fields are not updated.
type UpdateClientPatch struct {
	Name              *string
	RedirectURIs      *[]string
	AllowedScopes     *[]string
	AllowedGrantTypes *[]string
}

// UpdateFields applies the patch and returns the updated client. Only non-nil
// fields in the patch are written. updated_at is bumped on every call.
func (s *ClientStore) UpdateFields(ctx context.Context, q database.Querier, id string, p UpdateClientPatch) (*Client, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, ErrClientNotFound
	}
	// COALESCE keeps the SQL flat — nil args mean "no change".
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

// RotateSecret moves the current secret_hash into the previous slot with a
// TTL, and writes newHash as the current secret. Any existing previous secret
// is discarded.
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

// Disable sets the client status to 'disabled' and stamps disabled_at.
// Returns ErrClientNotFound if the client does not exist or is already disabled.
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

// Enable clears the disabled state and restores the client to 'active'.
// Returns ErrClientNotFound if the client does not exist or is already active.
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

// Delete hard-removes the client row. Authorization codes for this client
// are cascaded via the FK in migration 000017. Valkey refresh tokens for
// this client should be revoked post-commit by the caller via
// revokebefore.ClientSetNow.
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
