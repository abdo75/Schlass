package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdo75/Schlass/internal/oidc"
	"github.com/abdo75/Schlass/internal/store"
)

type OIDCDiscoveryHandler struct {
	publicURL       string
	pool            *pgxpool.Pool
	signingKeyStore *store.SigningKeyStore
}

func NewOIDCDiscoveryHandler(publicURL string, pool *pgxpool.Pool) *OIDCDiscoveryHandler {
	return &OIDCDiscoveryHandler{
		publicURL:       publicURL,
		pool:            pool,
		signingKeyStore: store.NewSigningKeyStore(),
	}
}

func (h *OIDCDiscoveryHandler) GetConfiguration(w http.ResponseWriter, r *http.Request) {
	meta := oidc.BuildDiscoveryMetadata(h.publicURL)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.NewEncoder(w).Encode(meta)
}

func (h *OIDCDiscoveryHandler) GetJWKS(w http.ResponseWriter, r *http.Request) {
	keys, err := h.signingKeyStore.ListPublishable(r.Context(), h.pool)
	if err != nil {
		slog.Error("jwks: list publishable", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	set, err := oidc.BuildJWKSet(keys)
	if err != nil {
		slog.Error("jwks: build set", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.NewEncoder(w).Encode(set)
}
