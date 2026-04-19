// Package handler — clients.go hosts the ClientsHandler for /api/clients/*
// admin endpoints.
package handler

import (
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

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

