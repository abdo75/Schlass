package handler

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdo75/Schlass/internal/middleware"
	"github.com/abdo75/Schlass/internal/oidc"
	"github.com/abdo75/Schlass/internal/store"
)

type signingKeyDTO struct {
	KID       string     `json:"kid"`
	Algorithm string     `json:"algorithm"`
	Status    string     `json:"status"`
	CreatedAt time.Time  `json:"created_at"`
	RotatedAt *time.Time `json:"rotated_at,omitempty"`
}

type AdminSigningKeysHandler struct {
	pool          *pgxpool.Pool
	auditStore    AuditLogger
	encryptionKey []byte
}

func NewAdminSigningKeysHandler(pool *pgxpool.Pool, auditStore AuditLogger, encryptionKey []byte) *AdminSigningKeysHandler {
	return &AdminSigningKeysHandler{pool: pool, auditStore: auditStore, encryptionKey: encryptionKey}
}

func (h *AdminSigningKeysHandler) Rotate(w http.ResponseWriter, r *http.Request) {
	actor, ok := middleware.CurrentUser(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}

	s := store.NewSigningKeyStore()

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

	cutoff := time.Now().Add(-(15*time.Minute + 24*time.Hour + 30*time.Second))
	if err := oidc.RetireSweep(r.Context(), h.pool, h.auditStore, cutoff); err != nil {
		slog.Warn("rotate: retire sweep failed", "error", err)
	}

	w.WriteHeader(http.StatusNoContent)
}

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

func (h *AdminSigningKeysHandler) EmergencyRetire(w http.ResponseWriter, r *http.Request) {
	actor, ok := middleware.CurrentUser(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}

	kidStr := pathParam(r, "kid")
	kid, err := uuid.Parse(kidStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid kid.")
		return
	}

	s := store.NewSigningKeyStore()

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("emergency-retire: begin tx", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	var status string
	err = tx.QueryRow(r.Context(), `SELECT status FROM signing_keys WHERE id = $1 FOR UPDATE`, kid).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "SIGNING_KEY_NOT_FOUND", "Signing key not found.")
		return
	}
	if err != nil {
		slog.Error("emergency-retire: select for update", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	switch status {
	case "active":
		writeError(w, http.StatusConflict, "CANNOT_RETIRE_ACTIVE_KEY", "Cannot retire the active signing key. Rotate first, then retire the demoted key.")
		return
	case "retired":
		writeError(w, http.StatusConflict, "ALREADY_RETIRED", "Signing key is already retired.")
		return
	case "retiring":
	default:
		slog.Error("emergency-retire: unknown status", "status", status, "kid", kid) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := s.MarkRetired(r.Context(), tx, kid); err != nil {
		slog.Error("emergency-retire: MarkRetired", "error", err, "kid", kid) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
		EventType:  "oidc.signing_key.retired",
		ActorID:    &actor.ID,
		ActorEmail: actor.Email,
		TargetType: "signing_key",
		TargetID:   kid.String(),
		IPAddress:  extractClientIP(r),
		Outcome:    "success",
		Metadata:   map[string]any{"reason": "emergency"},
	}); err != nil {
		slog.Error("emergency-retire: audit", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("emergency-retire: commit", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
