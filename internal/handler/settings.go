package handler

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdo75/Schlass/internal/config"
	"github.com/abdo75/Schlass/internal/middleware"
	"github.com/abdo75/Schlass/internal/model"
	"github.com/abdo75/Schlass/internal/store"
)

// SettingsHandler serves the admin Settings page: a single GET that
// returns the full snapshot across all four domains + four PATCH
// endpoints (general/security/tokens/email) that each write a subset of
// instance_config keys with per-key audit-in-tx.
//
// encryptionKey is retained on the struct so subsequent PATCH email
// handlers (T5) can AES-GCM-wrap the SMTP password via
// ConfigService.SetEncryptedValue. It is not used by GetAll or
// PatchGeneral.
type SettingsHandler struct {
	pool          *pgxpool.Pool
	configService *config.ConfigService
	auditStore    AuditLogger
	encryptionKey []byte
}

func NewSettingsHandler(pool *pgxpool.Pool, configService *config.ConfigService, auditStore AuditLogger, encryptionKey []byte) *SettingsHandler {
	return &SettingsHandler{pool: pool, configService: configService, auditStore: auditStore, encryptionKey: encryptionKey}
}

// GetAll serves GET /api/settings. Returns every settings-domain value in
// one call. SMTP password is surfaced as smtp_password_set: bool only —
// plaintext and ciphertext never leave the server.
func (h *SettingsHandler) GetAll(w http.ResponseWriter, r *http.Request) {
	snap, err := h.configService.GetSettingsSnapshot(r.Context(), h.pool)
	if err != nil {
		slog.Error("settings.GetAll", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

// PatchGeneral serves PATCH /api/settings/general. One-field payload (just
// instance_name). Establishes the config.<key>.changed audit-in-tx pattern
// every other settings PATCH (T3-T5) will follow. No-op when the value is
// unchanged — avoids audit noise from client-side retries and double-clicks.
func (h *SettingsHandler) PatchGeneral(w http.ResponseWriter, r *http.Request) {
	actor, ok := middleware.CurrentUser(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}
	ip := extractClientIP(r)

	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var in model.GeneralSettings
	if err := dec.Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body.")
		return
	}
	if err := model.ValidateGeneralSettings(&in); err != nil {
		writeValidationError(w, err)
		return
	}
	newName := strings.TrimSpace(in.InstanceName)

	oldName, err := h.configService.GetInstanceName(r.Context(), h.pool)
	if err != nil {
		slog.Error("settings.PatchGeneral: get old", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if newName == oldName {
		snap, _ := h.configService.GetSettingsSnapshot(r.Context(), h.pool)
		writeJSON(w, http.StatusOK, snap.General)
		return
	}

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("settings.PatchGeneral: begin tx", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	if err := h.configService.SetInstanceName(r.Context(), tx, newName); err != nil {
		slog.Error("settings.PatchGeneral: set", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
		EventType:  "config.instance_name.changed",
		ActorID:    &actor.ID,
		ActorEmail: actor.Email,
		TargetType: "instance_config",
		TargetID:   "instance_name",
		IPAddress:  ip,
		Outcome:    "success",
		Metadata:   map[string]any{"old_value": oldName, "new_value": newName},
	}); err != nil {
		slog.Error("settings.PatchGeneral: audit", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("settings.PatchGeneral: commit", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	snap, _ := h.configService.GetSettingsSnapshot(r.Context(), h.pool)
	writeJSON(w, http.StatusOK, snap.General)
}

// writeValidationError maps a *model.ValidationError to a 400 response with
// the stable UPPERCASE code that the SPA translates to an i18n key. Used
// by every settings PATCH handler (PatchGeneral today; PatchSecurity,
// PatchTokens, PatchEmail in T3-T5).
func writeValidationError(w http.ResponseWriter, err error) {
	var ve *model.ValidationError
	if errors.As(err, &ve) {
		code := ve.Code
		if code == "" {
			code = "VALIDATION_ERROR"
		} else {
			code = strings.ToUpper(code)
		}
		writeError(w, http.StatusBadRequest, code, ve.Error())
		return
	}
	writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
}
