package handler

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdo75/Schlass/internal/middleware"
	"github.com/abdo75/Schlass/internal/oidc"
	"github.com/abdo75/Schlass/internal/store"
)

// signingKeyDTO shapes the public /api/admin/signing-keys list response.
// Mirrors store.SigningKey minus secret material (private_key_encrypted
// never leaves the backend). RotatedAt is the moment the key was marked
// retiring; used by the SPA to compute the 24h+15m retirement countdown.
type signingKeyDTO struct {
	KID       string     `json:"kid"`
	Algorithm string     `json:"algorithm"`
	Status    string     `json:"status"`
	CreatedAt time.Time  `json:"created_at"`
	RotatedAt *time.Time `json:"rotated_at,omitempty"`
}

// AdminSigningKeysHandler serves POST /api/admin/signing-keys/rotate.
type AdminSigningKeysHandler struct {
	pool          *pgxpool.Pool
	auditStore    AuditLogger
	encryptionKey []byte
}

func NewAdminSigningKeysHandler(pool *pgxpool.Pool, auditStore AuditLogger, encryptionKey []byte) *AdminSigningKeysHandler {
	return &AdminSigningKeysHandler{pool: pool, auditStore: auditStore, encryptionKey: encryptionKey}
}

// Rotate generates a new active signing key and marks the previous one
// retiring. Opportunistically runs a retire-sweep post-commit so retiring
// keys older than TTL transition to retired on the same call.
func (h *AdminSigningKeysHandler) Rotate(w http.ResponseWriter, r *http.Request) {
	actor, ok := middleware.CurrentUser(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}

	s := store.NewSigningKeyStore()

	// CPU-bound work before opening the tx.
	pubPEM, privPEM, err := oidc.GenerateKeyPair()
	if err != nil {
		slog.Error("rotate: generate keypair", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	wrapped, err := oidc.WrapPrivateKey(privPEM, h.encryptionKey)
	if err != nil {
		slog.Error("rotate: wrap private key", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	current, err := s.GetActive(r.Context(), tx)
	if err != nil {
		slog.Error("rotate: GetActive", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := s.MarkRetiring(r.Context(), tx, current.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	newID, err := s.Insert(r.Context(), tx, pubPEM, wrapped, "active")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
		EventType:  "oidc.signing_key.rotated",
		ActorID:    &actor.ID,
		ActorEmail: actor.Email,
		TargetType: "signing_key",
		TargetID:   newID.String(),
		IPAddress:  extractClientIP(r),
		Outcome:    "success",
		Metadata:   map[string]any{"previous_id": current.ID.String()},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	// Post-commit opportunistic retire sweep — best-effort.
	// cutoff = now - (accessTTL + refreshTTL + clockSkew) = now - (15m + 24h + 30s).
	cutoff := time.Now().Add(-(15*time.Minute + 24*time.Hour + 30*time.Second))
	if err := oidc.RetireSweep(r.Context(), h.pool, h.auditStore, cutoff); err != nil {
		slog.Warn("rotate: retire sweep failed", "error", err)
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetList serves GET /api/admin/signing-keys — returns the publishable set
// (active + retiring) with metadata (created_at, rotated_at) that the
// public JWKS feed doesn't carry. Gated by signing_keys.list permission.
// Ordered active-first, then retiring by created_at ASC (same ordering
// the JWKS publisher uses — callers can rely on index 0 being the
// currently-active key).
func (h *AdminSigningKeysHandler) GetList(w http.ResponseWriter, r *http.Request) {
	keys, err := store.NewSigningKeyStore().ListPublishable(r.Context(), h.pool)
	if err != nil {
		slog.Error("signing_keys list", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	out := make([]signingKeyDTO, 0, len(keys))
	for _, k := range keys {
		out = append(out, signingKeyDTO{
			KID:       k.ID.String(),
			Algorithm: k.Algorithm,
			Status:    k.Status,
			CreatedAt: k.CreatedAt,
			RotatedAt: k.RotatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": out})
}
