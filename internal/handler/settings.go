package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdo75/Schlass/internal/config"
	"github.com/abdo75/Schlass/internal/mail"
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
// InstanceConfig.SetEncryptedValue. It is not used by GetAll or
// PatchGeneral.
type SettingsHandler struct {
	pool          *pgxpool.Pool
	instanceConfig *config.InstanceConfig
	auditStore    AuditLogger
	encryptionKey []byte
}

func NewSettingsHandler(pool *pgxpool.Pool, instanceConfig *config.InstanceConfig, auditStore AuditLogger, encryptionKey []byte) *SettingsHandler {
	return &SettingsHandler{pool: pool, instanceConfig: instanceConfig, auditStore: auditStore, encryptionKey: encryptionKey}
}

// GetAll serves GET /api/settings. Returns every settings-domain value in
// one call. SMTP password is surfaced as smtp_password_set: bool only —
// plaintext and ciphertext never leave the server.
func (h *SettingsHandler) GetAll(w http.ResponseWriter, r *http.Request) {
	snap, err := h.instanceConfig.Settings(r.Context(), h.pool)
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

	oldName, err := h.instanceConfig.InstanceName(r.Context(), h.pool)
	if err != nil {
		slog.Error("settings.PatchGeneral: get old", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if newName == oldName {
		snap, _ := h.instanceConfig.Settings(r.Context(), h.pool)
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

	if err := h.instanceConfig.SetInstanceName(r.Context(), tx, newName); err != nil {
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

	snap, _ := h.instanceConfig.Settings(r.Context(), h.pool)
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
	pre, err := h.instanceConfig.Settings(r.Context(), h.pool)
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
			return h.instanceConfig.SetBool(ctx, tx, "mfa_required", v)
		}})
	}
	if in.PasswordMinLength != nil && *in.PasswordMinLength != pre.Security.PasswordMinLength {
		v := *in.PasswordMinLength
		changes = append(changes, change{"password_min_length", pre.Security.PasswordMinLength, v, func(ctx context.Context, tx pgx.Tx) error {
			return h.instanceConfig.SetInt(ctx, tx, "password_min_length", v)
		}})
	}
	if in.PasswordRequireUpper != nil && *in.PasswordRequireUpper != pre.Security.PasswordRequireUpper {
		v := *in.PasswordRequireUpper
		changes = append(changes, change{"password_require_upper", pre.Security.PasswordRequireUpper, v, func(ctx context.Context, tx pgx.Tx) error {
			return h.instanceConfig.SetBool(ctx, tx, "password_require_upper", v)
		}})
	}
	if in.PasswordRequireDigit != nil && *in.PasswordRequireDigit != pre.Security.PasswordRequireDigit {
		v := *in.PasswordRequireDigit
		changes = append(changes, change{"password_require_digit", pre.Security.PasswordRequireDigit, v, func(ctx context.Context, tx pgx.Tx) error {
			return h.instanceConfig.SetBool(ctx, tx, "password_require_digit", v)
		}})
	}
	if in.LockoutThreshold != nil && *in.LockoutThreshold != pre.Security.LockoutThreshold {
		v := *in.LockoutThreshold
		changes = append(changes, change{"lockout_threshold", pre.Security.LockoutThreshold, v, func(ctx context.Context, tx pgx.Tx) error {
			return h.instanceConfig.SetInt(ctx, tx, "lockout_threshold", v)
		}})
	}
	if in.LockoutDurationSecs != nil && *in.LockoutDurationSecs != pre.Security.LockoutDurationSecs {
		v := *in.LockoutDurationSecs
		changes = append(changes, change{"lockout_duration_secs", pre.Security.LockoutDurationSecs, v, func(ctx context.Context, tx pgx.Tx) error {
			return h.instanceConfig.SetInt(ctx, tx, "lockout_duration_secs", v)
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

	snap, _ := h.instanceConfig.Settings(r.Context(), h.pool)
	writeJSON(w, http.StatusOK, snap.Security)
}

// PatchTokens serves PATCH /api/settings/tokens. Two numeric keys
// (access_token_ttl_secs + refresh_token_ttl_secs); per-field audit-in-tx
// mirroring PatchSecurity.
func (h *SettingsHandler) PatchTokens(w http.ResponseWriter, r *http.Request) {
	actor, ok := middleware.CurrentUser(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}
	ip := extractClientIP(r)

	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var in model.TokenSettings
	if err := dec.Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body.")
		return
	}
	if err := model.ValidateTokenSettings(&in); err != nil {
		writeValidationError(w, err)
		return
	}

	pre, err := h.instanceConfig.Settings(r.Context(), h.pool)
	if err != nil {
		slog.Error("settings.PatchTokens: snapshot", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	type change struct {
		key   string
		oldV  any
		newV  any
		write func(ctx context.Context, tx pgx.Tx) error
	}
	var changes []change
	if in.AccessTokenTTLSecs != nil && *in.AccessTokenTTLSecs != pre.Tokens.AccessTokenTTLSecs {
		v := *in.AccessTokenTTLSecs
		changes = append(changes, change{"access_token_ttl_secs", pre.Tokens.AccessTokenTTLSecs, v, func(ctx context.Context, tx pgx.Tx) error {
			return h.instanceConfig.SetInt(ctx, tx, "access_token_ttl_secs", v)
		}})
	}
	if in.RefreshTokenTTLSecs != nil && *in.RefreshTokenTTLSecs != pre.Tokens.RefreshTokenTTLSecs {
		v := *in.RefreshTokenTTLSecs
		changes = append(changes, change{"refresh_token_ttl_secs", pre.Tokens.RefreshTokenTTLSecs, v, func(ctx context.Context, tx pgx.Tx) error {
			return h.instanceConfig.SetInt(ctx, tx, "refresh_token_ttl_secs", v)
		}})
	}

	if len(changes) == 0 {
		writeJSON(w, http.StatusOK, pre.Tokens)
		return
	}

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("settings.PatchTokens: begin tx", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	for _, c := range changes {
		if err := c.write(r.Context(), tx); err != nil {
			slog.Error("settings.PatchTokens: write", "error", err, "key", c.key)
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
			slog.Error("settings.PatchTokens: audit", "error", err, "key", c.key)
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("settings.PatchTokens: commit", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	snap, _ := h.instanceConfig.Settings(r.Context(), h.pool)
	writeJSON(w, http.StatusOK, snap.Tokens)
}

// PatchEmail serves PATCH /api/settings/email. Four plain fields
// (host/port/username/from) + one encrypted field (password). Password
// semantic: empty string keeps the current value; non-empty replaces and
// re-encrypts via InstanceConfig.SetEncryptedValue (AES-256-GCM). Audit
// metadata on smtp_password is {"changed": true} — never the plaintext or
// ciphertext in either direction; the TestPatchEmail_KeepCurrentPasswordOnEmpty
// integration test grep-asserts this and fails loudly on regression.
func (h *SettingsHandler) PatchEmail(w http.ResponseWriter, r *http.Request) {
	actor, ok := middleware.CurrentUser(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}
	ip := extractClientIP(r)

	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var in model.EmailSettings
	if err := dec.Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body.")
		return
	}
	if err := model.ValidateEmailSettings(&in); err != nil {
		writeValidationError(w, err)
		return
	}

	pre, err := h.instanceConfig.Settings(r.Context(), h.pool)
	if err != nil {
		slog.Error("settings.PatchEmail: snapshot", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	type change struct {
		key   string
		meta  map[string]any
		write func(ctx context.Context, tx pgx.Tx) error
	}
	var changes []change

	if in.SMTPHost != nil {
		v := strings.TrimSpace(*in.SMTPHost)
		if v != pre.Email.SMTPHost {
			changes = append(changes, change{
				key:  "smtp_host",
				meta: map[string]any{"old_value": pre.Email.SMTPHost, "new_value": v},
				write: func(ctx context.Context, tx pgx.Tx) error {
					return h.instanceConfig.SetString(ctx, tx, "smtp_host", v)
				},
			})
		}
	}
	if in.SMTPPort != nil && *in.SMTPPort != pre.Email.SMTPPort {
		v := *in.SMTPPort
		changes = append(changes, change{
			key:  "smtp_port",
			meta: map[string]any{"old_value": pre.Email.SMTPPort, "new_value": v},
			write: func(ctx context.Context, tx pgx.Tx) error {
				return h.instanceConfig.SetInt(ctx, tx, "smtp_port", v)
			},
		})
	}
	if in.SMTPUsername != nil && *in.SMTPUsername != pre.Email.SMTPUsername {
		v := *in.SMTPUsername
		changes = append(changes, change{
			key:  "smtp_username",
			meta: map[string]any{"old_value": pre.Email.SMTPUsername, "new_value": v},
			write: func(ctx context.Context, tx pgx.Tx) error {
				return h.instanceConfig.SetString(ctx, tx, "smtp_username", v)
			},
		})
	}
	if in.SMTPFrom != nil {
		v := strings.TrimSpace(*in.SMTPFrom)
		if v != pre.Email.SMTPFrom {
			changes = append(changes, change{
				key:  "smtp_from",
				meta: map[string]any{"old_value": pre.Email.SMTPFrom, "new_value": v},
				write: func(ctx context.Context, tx pgx.Tx) error {
					return h.instanceConfig.SetString(ctx, tx, "smtp_from", v)
				},
			})
		}
	}
	// Password: empty string = keep current (no change, no audit row).
	// Non-empty = replace. Audit metadata records only the fact of change —
	// never the plaintext or ciphertext.
	if in.SMTPPassword != nil && *in.SMTPPassword != "" {
		v := *in.SMTPPassword
		changes = append(changes, change{
			key:  "smtp_password",
			meta: map[string]any{"changed": true},
			write: func(ctx context.Context, tx pgx.Tx) error {
				return h.instanceConfig.SetEncryptedValue(ctx, tx, "smtp_password", v)
			},
		})
	}

	if len(changes) == 0 {
		writeJSON(w, http.StatusOK, pre.Email)
		return
	}

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("settings.PatchEmail: begin tx", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	for _, c := range changes {
		if err := c.write(r.Context(), tx); err != nil {
			slog.Error("settings.PatchEmail: write", "error", err, "key", c.key)
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
			Metadata:   c.meta,
		}); err != nil {
			slog.Error("settings.PatchEmail: audit", "error", err, "key", c.key)
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("settings.PatchEmail: commit", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	snap, _ := h.instanceConfig.Settings(r.Context(), h.pool)
	writeJSON(w, http.StatusOK, snap.Email)
}

// categorizeSMTPError maps a mail-package error to a stable client-facing
// code + safe human message. The raw err.Error() can embed internal DNS
// names, IPs, and STARTTLS certificate chain details — admin-only, but
// still undesirable on any UI surface that an XSS or admin-session theft
// could scrape.
func categorizeSMTPError(err error) (code, msg string) {
	s := err.Error()
	switch {
	case strings.Contains(s, "dial smtp"):
		return "SMTP_DIAL_FAILED", "Could not reach the SMTP server. Check host and port."
	case strings.Contains(s, "starttls"):
		return "SMTP_TLS_FAILED", "TLS handshake failed. Check the server certificate and port."
	case strings.Contains(s, "auth"):
		return "SMTP_AUTH_FAILED", "SMTP authentication failed. Check username and password."
	case strings.Contains(s, "mail from"), strings.Contains(s, "rcpt"):
		return "SMTP_ADDRESS_REJECTED", "The server rejected the sender or recipient address."
	default:
		return "SMTP_DELIVERY_FAILED", "SMTP delivery failed. Check server logs for details."
	}
}

// TestEmail serves POST /api/settings/email/test. Sends a one-off message
// to the currently-authenticated admin's own email using the saved SMTP
// config. Returns 400 SMTP_CONFIG_INCOMPLETE if required fields are unset,
// 502 on transport / auth error with a stable code that does not leak
// internal addresses or TLS details.
//
// Admin-only (gated by settings.write) — no per-IP rate limit in v1.
// last_tested_at surfacing is deferred to M6+ (Email tab status line reads
// the `delivered_at` in the response body for the initial UX).
func (h *SettingsHandler) TestEmail(w http.ResponseWriter, r *http.Request) {
	actor, ok := middleware.CurrentUser(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}

	sender, err := mail.NewSenderFromConfig(r.Context(), h.instanceConfig, h.pool)
	if err != nil {
		if errors.Is(err, mail.ErrSMTPConfigIncomplete) {
			writeError(w, http.StatusBadRequest, "SMTP_CONFIG_INCOMPLETE", "Complete and save the SMTP configuration before testing.")
			return
		}
		slog.Error("settings.TestEmail: new sender", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	instanceName, _ := h.instanceConfig.InstanceName(r.Context(), h.pool)
	if instanceName == "" {
		instanceName = "Schlass"
	}
	if err := sender.TestConnection(r.Context(), actor.Email, instanceName); err != nil {
		slog.Error("settings.TestEmail: send", "error", err, "actor", actor.Email)
		code, msg := categorizeSMTPError(err)
		writeError(w, http.StatusBadGateway, code, msg)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"delivered_at": time.Now().UTC().Format(time.RFC3339)})
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
