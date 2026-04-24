package authserver

import (
	"encoding/json"
	"log/slog"
	"net/http"

	signingkeys "github.com/abdo75/Schlass/internal/signingkeys"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdo75/Schlass/internal/httputil"
	"github.com/abdo75/Schlass/internal/oidc"
)

// DiscoveryHandler serves GET /.well-known/openid-configuration and
// GET /.well-known/jwks.json (OIDC discovery + JWKS endpoints).
type DiscoveryHandler struct {
	publicURL       string
	pool            *pgxpool.Pool
	signingKeyStore *signingkeys.Store
}

func NewDiscoveryHandler(publicURL string, pool *pgxpool.Pool) *DiscoveryHandler {
	return &DiscoveryHandler{
		publicURL:       publicURL,
		pool:            pool,
		signingKeyStore: signingkeys.NewStore(),
	}
}

func (h *DiscoveryHandler) GetConfiguration(w http.ResponseWriter, r *http.Request) {
	meta := oidc.BuildDiscoveryMetadata(h.publicURL)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.NewEncoder(w).Encode(meta)
}

func (h *DiscoveryHandler) GetJWKS(w http.ResponseWriter, r *http.Request) {
	keys, err := h.signingKeyStore.ListPublishable(r.Context(), h.pool)
	if err != nil {
		slog.Error("jwks: list publishable", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	set, err := signingkeys.BuildJWKSet(keys)
	if err != nil {
		slog.Error("jwks: build set", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.NewEncoder(w).Encode(set)
}
