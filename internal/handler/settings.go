package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
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

// PatchSecurity serves PATCH /api/settings/security. Six possible keys;
// every non-nil field that differs from the current value emits one
// config.<key>.changed audit row inside a single PG tx. Fields that
// match the current value are skipped — no audit noise on no-op saves.
// This is the template T4 (tokens) and T5 (email) clone.
func (h *SettingsHandler) PatchSecurity(w http.ResponseWriter, r *http.Request) {
	actor, ok := middleware.CurrentUser(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}
	ip := extractClientIP(r)

	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var in model.SecuritySettings
	if err := dec.Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body.")
		return
	}
	if err := model.ValidateSecuritySettings(&in); err != nil {
		writeValidationError(w, err)
		return
	}

	// Snapshot pre-values — needed for both change-detection and audit metadata.
	pre, err := h.configService.GetSettingsSnapshot(r.Context(), h.pool)
	if err != nil {
		slog.Error("settings.PatchSecurity: snapshot", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	// Build the change list before opening the tx so no-op saves skip tx
	// overhead entirely.
	type change struct {
		key   string
		oldV  any
		newV  any
		write func(ctx context.Context, tx pgx.Tx) error
	}
	var changes []change
	if in.MFARequired != nil && *in.MFARequired != pre.Security.MFARequired {
		v := *in.MFARequired
		changes = append(changes, change{"mfa_required", pre.Security.MFARequired, v, func(ctx context.Context, tx pgx.Tx) error {
			return h.configService.SetBool(ctx, tx, "mfa_required", v)
		}})
	}
	if in.PasswordMinLength != nil && *in.PasswordMinLength != pre.Security.PasswordMinLength {
		v := *in.PasswordMinLength
		changes = append(changes, change{"password_min_length", pre.Security.PasswordMinLength, v, func(ctx context.Context, tx pgx.Tx) error {
			return h.configService.SetInt(ctx, tx, "password_min_length", v)
		}})
	}
	if in.PasswordRequireUpper != nil && *in.PasswordRequireUpper != pre.Security.PasswordRequireUpper {
		v := *in.PasswordRequireUpper
		changes = append(changes, change{"password_require_upper", pre.Security.PasswordRequireUpper, v, func(ctx context.Context, tx pgx.Tx) error {
			return h.configService.SetBool(ctx, tx, "password_require_upper", v)
		}})
	}
	if in.PasswordRequireDigit != nil && *in.PasswordRequireDigit != pre.Security.PasswordRequireDigit {
		v := *in.PasswordRequireDigit
		changes = append(changes, change{"password_require_digit", pre.Security.PasswordRequireDigit, v, func(ctx context.Context, tx pgx.Tx) error {
			return h.configService.SetBool(ctx, tx, "password_require_digit", v)
		}})
	}
	if in.LockoutThreshold != nil && *in.LockoutThreshold != pre.Security.LockoutThreshold {
		v := *in.LockoutThreshold
		changes = append(changes, change{"lockout_threshold", pre.Security.LockoutThreshold, v, func(ctx context.Context, tx pgx.Tx) error {
			return h.configService.SetInt(ctx, tx, "lockout_threshold", v)
		}})
	}
	if in.LockoutDurationSecs != nil && *in.LockoutDurationSecs != pre.Security.LockoutDurationSecs {
		v := *in.LockoutDurationSecs
		changes = append(changes, change{"lockout_duration_secs", pre.Security.LockoutDurationSecs, v, func(ctx context.Context, tx pgx.Tx) error {
			return h.configService.SetInt(ctx, tx, "lockout_duration_secs", v)
		}})
	}

	if len(changes) == 0 {
		writeJSON(w, http.StatusOK, pre.Security)
		return
	}

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("settings.PatchSecurity: begin tx", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	for _, c := range changes {
		if err := c.write(r.Context(), tx); err != nil {
			slog.Error("settings.PatchSecurity: write", "error", err, "key", c.key)
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		if err := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
			EventType:  "config." + c.key + ".changed",
			ActorID:    &actor.ID,
			ActorEmail: actor.Email,
			TargetType: "instance_config",
			TargetID:   c.key,
			IPAddress:  ip,
			Outcome:    "success",
			Metadata:   map[string]any{"old_value": c.oldV, "new_value": c.newV},
		}); err != nil {
			slog.Error("settings.PatchSecurity: audit", "error", err, "key", c.key)
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("settings.PatchSecurity: commit", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	snap, _ := h.configService.GetSettingsSnapshot(r.Context(), h.pool)
	writeJSON(w, http.StatusOK, snap.Security)
}

// writeValidationError maps a *model.ValidationError to a 400 response.
// Validator Code is SCREAMING_SNAKE_CASE by convention (matches existing
// codes across the codebase: INVALID_SESSION, USER_NOT_FOUND, etc.); passes
// through unchanged. Used by every settings PATCH handler (PatchGeneral
// today; PatchSecurity, PatchTokens, PatchEmail in T3-T5).
func writeValidationError(w http.ResponseWriter, err error) {
	var ve *model.ValidationError
	if errors.As(err, &ve) {
		code := ve.Code
		if code == "" {
			code = "VALIDATION_ERROR"
		}
		writeError(w, http.StatusBadRequest, code, ve.Error())
		return
	}
	writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
}
