package handler

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/abdo75/Schlass/internal/crypto"
	"github.com/abdo75/Schlass/internal/middleware"
	"github.com/abdo75/Schlass/internal/model"
	"github.com/abdo75/Schlass/internal/revokebefore"
	"github.com/abdo75/Schlass/internal/store"
)

type ClientsHandler struct {
	pool        *pgxpool.Pool
	valkey      *redis.Client
	clientStore *store.ClientStore
	auditStore  AuditLogger
	publicURL   *url.URL
}

func NewClientsHandler(pool *pgxpool.Pool, valkey *redis.Client, cs *store.ClientStore, as AuditLogger, publicURL *url.URL) *ClientsHandler {
	return &ClientsHandler{
		pool:        pool,
		valkey:      valkey,
		clientStore: cs,
		auditStore:  as,
		publicURL:   publicURL,
	}
}

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

func parseClientID(w http.ResponseWriter, r *http.Request) (string, bool) {
	raw := r.PathValue("id")
	if _, err := uuid.Parse(raw); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid client id.")
		return "", false
	}
	return raw, true
}

const (
	// 24h grace window during which a rotated client's previous secret is
	// still accepted at /token.
	clientSecretOverlapTTL = 24 * time.Hour

	clientRequestMaxBytes = 64 * 1024
)

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

func generateClientSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

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

// PostCreate returns the generated secret plaintext ONCE in the response.
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

type patchClientReq struct {
	Name              *string   `json:"name,omitempty"`
	RedirectURIs      *[]string `json:"redirect_uris,omitempty"`
	AllowedScopes     *[]string `json:"allowed_scopes,omitempty"`
	AllowedGrantTypes *[]string `json:"allowed_grant_types,omitempty"`
}

// PatchOne row-locks under SELECT FOR UPDATE to serialize concurrent PATCHes.
// Emits one audit row per changed field in canonical order (name →
// redirect_uris → scopes → grants). Immutable fields are rejected by
// DisallowUnknownFields + the 64KB body cap.
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

// PostDisable is reversible via PostEnable. Outstanding access tokens
// expire naturally within 15min; /token refresh grant rejects disabled
// clients via existing GetByID.
func (h *ClientsHandler) PostDisable(w http.ResponseWriter, r *http.Request) {
	current, ok := middleware.CurrentUser(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}
	id, ok := parseClientID(w, r)
	if !ok {
		return
	}
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	if err := h.clientStore.Disable(r.Context(), tx, id); err != nil {
		if errors.Is(err, store.ErrClientNotFound) {
			writeError(w, http.StatusNotFound, "clients.not_found", "Client not found or already disabled.")
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
		EventType:  "client.disabled",
		ActorID:    &current.ID,
		ActorEmail: current.Email,
		TargetType: "client",
		TargetID:   id,
		IPAddress:  extractClientIP(r),
		Outcome:    "success",
		Metadata:   map[string]any{},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *ClientsHandler) PostEnable(w http.ResponseWriter, r *http.Request) {
	current, ok := middleware.CurrentUser(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}
	id, ok := parseClientID(w, r)
	if !ok {
		return
	}
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	old, err := h.clientStore.GetByIDAny(r.Context(), tx, id)
	if errors.Is(err, store.ErrClientNotFound) {
		writeError(w, http.StatusNotFound, "clients.not_found", "Client not found.")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.clientStore.Enable(r.Context(), tx, id); err != nil {
		if errors.Is(err, store.ErrClientNotFound) {
			writeError(w, http.StatusConflict, "clients.validation_error", "Client is not disabled.")
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	meta := map[string]any{}
	if old.DisabledAt != nil {
		meta["previously_disabled_at"] = old.DisabledAt
	}
	if err := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
		EventType:  "client.enabled",
		ActorID:    &current.ID,
		ActorEmail: current.Email,
		TargetType: "client",
		TargetID:   id,
		IPAddress:  extractClientIP(r),
		Outcome:    "success",
		Metadata:   meta,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type rotateSecretResp struct {
	ClientID                string    `json:"client_id"`
	ClientSecret            string    `json:"client_secret"`
	PreviousSecretExpiresAt time.Time `json:"previous_secret_expires_at"`
}

// PostRotateSecret moves existing secret → previous with 24h TTL, mints a
// new 32-byte secret, returns the plaintext ONCE. A second rotate discards
// any pre-existing previous.
func (h *ClientsHandler) PostRotateSecret(w http.ResponseWriter, r *http.Request) {
	current, ok := middleware.CurrentUser(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}
	id, ok := parseClientID(w, r)
	if !ok {
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

	existing, err := h.clientStore.GetByIDAny(r.Context(), tx, id)
	if errors.Is(err, store.ErrClientNotFound) {
		writeError(w, http.StatusNotFound, "clients.not_found", "Client not found.")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if existing.ClientType != "confidential" {
		writeError(w, http.StatusBadRequest, "clients.client_type_locked", "Only confidential clients have secrets to rotate.")
		return
	}

	rotated, err := h.clientStore.RotateSecret(r.Context(), tx, id, secretHash, clientSecretOverlapTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	meta := map[string]any{}
	if rotated.SecretPreviousExpiresAt != nil {
		meta["previous_expires_at"] = rotated.SecretPreviousExpiresAt
	}
	if err := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
		EventType:  "client.secret_rotated",
		ActorID:    &current.ID,
		ActorEmail: current.Email,
		TargetType: "client",
		TargetID:   id,
		IPAddress:  extractClientIP(r),
		Outcome:    "success",
		Metadata:   meta,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	resp := rotateSecretResp{
		ClientID:     id,
		ClientSecret: rawSecret,
	}
	if rotated.SecretPreviousExpiresAt != nil {
		resp.PreviousSecretExpiresAt = *rotated.SecretPreviousExpiresAt
	}
	writeJSON(w, http.StatusOK, resp)
}

// DeleteOne hard-deletes (cascades pending auth codes via FK). Post-commit
// bumps client:revoke_before so outstanding access tokens fail on next use.
func (h *ClientsHandler) DeleteOne(w http.ResponseWriter, r *http.Request) {
	current, ok := middleware.CurrentUser(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}
	id, ok := parseClientID(w, r)
	if !ok {
		return
	}
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	old, err := h.clientStore.GetByIDAny(r.Context(), tx, id)
	if errors.Is(err, store.ErrClientNotFound) {
		writeError(w, http.StatusNotFound, "clients.not_found", "Client not found.")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.clientStore.Delete(r.Context(), tx, id); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	meta := map[string]any{"name": old.Name}
	if old.DisabledAt != nil {
		meta["previously_disabled_at"] = old.DisabledAt
	}
	if err := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
		EventType:  "client.deleted",
		ActorID:    &current.ID,
		ActorEmail: current.Email,
		TargetType: "client",
		TargetID:   id,
		IPAddress:  extractClientIP(r),
		Outcome:    "success",
		Metadata:   meta,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	// Best-effort — PG-committed delete is the load-bearing event.
	if err := revokebefore.ClientSetNow(context.Background(), h.valkey, id); err != nil {
		slog.Error("delete client: revoke_before set failed", "err", err, "client_id", id) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
	}

	w.WriteHeader(http.StatusNoContent)
}
