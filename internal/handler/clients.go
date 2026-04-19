// Package handler — clients.go hosts the ClientsHandler for /api/clients/*
// admin endpoints.
package handler

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/abdo75/Schlass/internal/crypto"
	"github.com/abdo75/Schlass/internal/middleware"
	"github.com/abdo75/Schlass/internal/model"
	"github.com/abdo75/Schlass/internal/store"
)

// ClientsHandler serves the admin-only /api/clients/* endpoints. Constructed
// in internal/server/router.go and wrapped with middleware.Auth +
// middleware.RequirePermission gates at wiring time.
type ClientsHandler struct {
	pool        *pgxpool.Pool
	valkey      *redis.Client
	clientStore *store.ClientStore
	auditStore  AuditLogger
	publicURL   *url.URL
}

// NewClientsHandler wires the dependencies. All fields are required.
func NewClientsHandler(pool *pgxpool.Pool, valkey *redis.Client, cs *store.ClientStore, as AuditLogger, publicURL *url.URL) *ClientsHandler {
	return &ClientsHandler{
		pool:        pool,
		valkey:      valkey,
		clientStore: cs,
		auditStore:  as,
		publicURL:   publicURL,
	}
}

// --- response DTO (T5.2) ----------------------------------------------------

type clientDTO struct {
	ID                      string     `json:"id"`
	Name                    string     `json:"name"`
	ClientType              string     `json:"client_type"`
	RedirectURIs            []string   `json:"redirect_uris"`
	AllowedGrantTypes       []string   `json:"allowed_grant_types"`
	AllowedScopes           []string   `json:"allowed_scopes"`
	TokenEndpointAuthMethod string     `json:"token_endpoint_auth_method"`
	Status                  string     `json:"status"`
	DisabledAt              *time.Time `json:"disabled_at,omitempty"`
	CreatedByUserID         *string    `json:"created_by_user_id,omitempty"`
	CreatedAt               time.Time  `json:"created_at"`
	UpdatedAt               time.Time  `json:"updated_at"`
}

func toClientDTO(c *store.Client) clientDTO {
	var createdBy *string
	if c.CreatedByUserID != nil {
		s := c.CreatedByUserID.String()
		createdBy = &s
	}
	return clientDTO{
		ID:                      c.ID.String(),
		Name:                    c.Name,
		ClientType:              c.ClientType,
		RedirectURIs:            c.RedirectURIs,
		AllowedGrantTypes:       c.AllowedGrantTypes,
		AllowedScopes:           c.AllowedScopes,
		TokenEndpointAuthMethod: c.TokenEndpointAuthMethod,
		Status:                  c.Status,
		DisabledAt:              c.DisabledAt,
		CreatedByUserID:         createdBy,
		CreatedAt:               c.CreatedAt,
		UpdatedAt:               c.UpdatedAt,
	}
}

// --- shared helpers (T5.2) --------------------------------------------------

// parseClientID extracts the :id path segment and validates it as a UUID.
func parseClientID(w http.ResponseWriter, r *http.Request) (string, bool) {
	raw := r.PathValue("id")
	if _, err := uuid.Parse(raw); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid client id.")
		return "", false
	}
	return raw, true
}

// --- deferred helpers (T5.4) ------------------------------------------------

const (
	// clientRequestMaxBytes caps create/update bodies to defend against
	// memory-exhaustion via giant JSON.
	clientRequestMaxBytes = 64 * 1024
)

// strictJSON decodes a JSON request body with DisallowUnknownFields and a
// MaxBytesReader cap. On failure writes 400 and returns false.
func strictJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, clientRequestMaxBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "VALIDATION_ERROR", "Request body too large.")
		} else {
			writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body.")
		}
		return false
	}
	if dec.More() {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Request body contains extra content.")
		return false
	}
	return true
}

// generateClientSecret mints a 32-byte random secret, base64url-encoded.
func generateClientSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// --- read handlers (T5.3) ---------------------------------------------------

// GetList serves GET /api/clients?status=active|disabled|all. Default filter
// is "active".
func (h *ClientsHandler) GetList(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	if status == "" {
		status = "active"
	}
	if status != "active" && status != "disabled" && status != "all" {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid status filter.")
		return
	}
	clients, err := h.clientStore.List(r.Context(), h.pool, status)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	out := make([]clientDTO, 0, len(clients))
	for _, c := range clients {
		out = append(out, toClientDTO(c))
	}
	writeJSON(w, http.StatusOK, map[string]any{"clients": out})
}

// GetOne serves GET /api/clients/:id. Admin path — surfaces any status.
func (h *ClientsHandler) GetOne(w http.ResponseWriter, r *http.Request) {
	id, ok := parseClientID(w, r)
	if !ok {
		return
	}
	c, err := h.clientStore.GetByIDAny(r.Context(), h.pool, id)
	if errors.Is(err, store.ErrClientNotFound) {
		writeError(w, http.StatusNotFound, "clients.not_found", "Client not found.")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"client": toClientDTO(c)})
}

// --- write handlers (T5.4) --------------------------------------------------

type createClientReq struct {
	Name              string   `json:"name"`
	ClientType        string   `json:"client_type"`
	RedirectURIs      []string `json:"redirect_uris"`
	AllowedGrantTypes []string `json:"allowed_grant_types"`
	AllowedScopes     []string `json:"allowed_scopes"`
}

type createClientResp struct {
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret"`
	Client       clientDTO `json:"client"`
}

// PostCreate serves POST /api/clients. Mints a 32-byte secret, Argon2id-hashes
// it, and returns the plaintext ONCE in the response body. Audit-in-tx.
func (h *ClientsHandler) PostCreate(w http.ResponseWriter, r *http.Request) {
	current, ok := middleware.CurrentUser(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}

	var req createClientReq
	if !strictJSON(w, r, &req) {
		return
	}

	// Validate fields.
	name, err := model.ValidateClientName(req.Name)
	if err != nil {
		writeError(w, http.StatusBadRequest, "clients.validation_error", err.Error())
		return
	}
	if req.ClientType != "confidential" {
		writeError(w, http.StatusBadRequest, "clients.validation_error", "Only confidential clients are supported.")
		return
	}
	if len(req.RedirectURIs) == 0 {
		writeError(w, http.StatusBadRequest, "clients.validation_error", "At least one redirect_uri is required.")
		return
	}
	if len(req.RedirectURIs) > 10 {
		writeError(w, http.StatusBadRequest, "clients.validation_error", "Maximum 10 redirect URIs.")
		return
	}
	for _, u := range req.RedirectURIs {
		if err := ValidateRedirectURIInput(u); err != nil {
			writeError(w, http.StatusBadRequest, "clients.redirect_uri_invalid", err.Error())
			return
		}
	}
	if err := model.ValidateScopes(req.AllowedScopes); err != nil {
		writeError(w, http.StatusBadRequest, "clients.scope_invalid", err.Error())
		return
	}
	if err := model.ValidateGrantTypes(req.AllowedGrantTypes); err != nil {
		writeError(w, http.StatusBadRequest, "clients.grant_invalid", err.Error())
		return
	}

	rawSecret, err := generateClientSecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	secretHash, err := crypto.HashPassword(rawSecret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	c, err := h.clientStore.Create(r.Context(), tx, store.CreateClientParams{
		Name:                    name,
		ClientType:              req.ClientType,
		SecretHash:              secretHash,
		RedirectURIs:            req.RedirectURIs,
		AllowedGrantTypes:       req.AllowedGrantTypes,
		AllowedScopes:           req.AllowedScopes,
		TokenEndpointAuthMethod: "client_secret_post",
		CreatedByUserID:         &current.ID,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
		EventType:  "client.created",
		ActorID:    &current.ID,
		ActorEmail: current.Email,
		TargetType: "client",
		TargetID:   c.ID.String(),
		IPAddress:  extractClientIP(r),
		Outcome:    "success",
		Metadata: map[string]any{
			"name":                c.Name,
			"client_type":         c.ClientType,
			"redirect_uris_count": len(c.RedirectURIs),
			"scopes":              c.AllowedScopes,
			"grants":              c.AllowedGrantTypes,
		},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	writeJSON(w, http.StatusCreated, createClientResp{
		ClientID:     c.ID.String(),
		ClientSecret: rawSecret,
		Client:       toClientDTO(c),
	})
}

// --- write handlers (T5.5) --------------------------------------------------

type patchClientReq struct {
	Name              *string   `json:"name,omitempty"`
	RedirectURIs      *[]string `json:"redirect_uris,omitempty"`
	AllowedScopes     *[]string `json:"allowed_scopes,omitempty"`
	AllowedGrantTypes *[]string `json:"allowed_grant_types,omitempty"`
}

// PatchOne serves PATCH /api/clients/:id. Partial merge. Uses SELECT ... FOR
// UPDATE inside the tx to serialize concurrent PATCHes. Emits one audit row
// per changed field, in canonical order: name → redirect_uris → scopes →
// grants. No-op PATCH commits with zero audit rows.
//
// Immutable fields: client_type, token_endpoint_auth_method, status,
// secret_hash, secret_hash_previous. DisallowUnknownFields + 64KB body cap
// reject attempts to patch these (plus typos like "redirect_urls").
func (h *ClientsHandler) PatchOne(w http.ResponseWriter, r *http.Request) {
	current, ok := middleware.CurrentUser(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}
	id, ok := parseClientID(w, r)
	if !ok {
		return
	}

	var req patchClientReq
	if !strictJSON(w, r, &req) {
		return
	}

	// Validate non-nil fields up front.
	if req.Name != nil {
		v, err := model.ValidateClientName(*req.Name)
		if err != nil {
			writeError(w, http.StatusBadRequest, "clients.validation_error", err.Error())
			return
		}
		req.Name = &v
	}
	if req.RedirectURIs != nil {
		if len(*req.RedirectURIs) == 0 || len(*req.RedirectURIs) > 10 {
			writeError(w, http.StatusBadRequest, "clients.validation_error", "redirect_uris must have 1-10 entries.")
			return
		}
		for _, u := range *req.RedirectURIs {
			if err := ValidateRedirectURIInput(u); err != nil {
				writeError(w, http.StatusBadRequest, "clients.redirect_uri_invalid", err.Error())
				return
			}
		}
	}
	if req.AllowedScopes != nil {
		if err := model.ValidateScopes(*req.AllowedScopes); err != nil {
			writeError(w, http.StatusBadRequest, "clients.scope_invalid", err.Error())
			return
		}
	}
	if req.AllowedGrantTypes != nil {
		if err := model.ValidateGrantTypes(*req.AllowedGrantTypes); err != nil {
			writeError(w, http.StatusBadRequest, "clients.grant_invalid", err.Error())
			return
		}
	}

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	old, err := h.clientStore.GetByIDForUpdate(r.Context(), tx, id)
	if errors.Is(err, store.ErrClientNotFound) {
		writeError(w, http.StatusNotFound, "clients.not_found", "Client not found.")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	updated, err := h.clientStore.UpdateFields(r.Context(), tx, id, store.UpdateClientPatch{
		Name:              req.Name,
		RedirectURIs:      req.RedirectURIs,
		AllowedScopes:     req.AllowedScopes,
		AllowedGrantTypes: req.AllowedGrantTypes,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	// Per-field audit in canonical order: name, redirect_uris, scopes, grants.
	if old.Name != updated.Name {
		if err := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
			EventType:  "client.name_updated",
			ActorID:    &current.ID,
			ActorEmail: current.Email,
			TargetType: "client",
			TargetID:   id,
			IPAddress:  extractClientIP(r),
			Outcome:    "success",
			Metadata:   map[string]any{"from": old.Name, "to": updated.Name},
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
	}
	if !slicesEqual(old.RedirectURIs, updated.RedirectURIs) {
		if err := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
			EventType:  "client.redirect_uris_updated",
			ActorID:    &current.ID,
			ActorEmail: current.Email,
			TargetType: "client",
			TargetID:   id,
			IPAddress:  extractClientIP(r),
			Outcome:    "success",
			Metadata:   map[string]any{"from": old.RedirectURIs, "to": updated.RedirectURIs},
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
	}
	if !slicesEqual(old.AllowedScopes, updated.AllowedScopes) {
		if err := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
			EventType:  "client.scopes_updated",
			ActorID:    &current.ID,
			ActorEmail: current.Email,
			TargetType: "client",
			TargetID:   id,
			IPAddress:  extractClientIP(r),
			Outcome:    "success",
			Metadata:   map[string]any{"from": old.AllowedScopes, "to": updated.AllowedScopes},
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
	}
	if !slicesEqual(old.AllowedGrantTypes, updated.AllowedGrantTypes) {
		if err := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
			EventType:  "client.grants_updated",
			ActorID:    &current.ID,
			ActorEmail: current.Email,
			TargetType: "client",
			TargetID:   id,
			IPAddress:  extractClientIP(r),
			Outcome:    "success",
			Metadata:   map[string]any{"from": old.AllowedGrantTypes, "to": updated.AllowedGrantTypes},
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
	}

	if err := tx.Commit(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"client": toClientDTO(updated)})
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
