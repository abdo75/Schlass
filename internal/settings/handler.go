// Package settings serves /api/settings. Every PATCH emits one
// config.<key>.changed audit row per changed field in the same tx; unchanged
// fields write no audit row (no-op save produces no audit noise).
package settings

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/abdo75/Schlass/internal/instanceconfig"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdo75/Schlass/internal/apierrors"
	"github.com/abdo75/Schlass/internal/audit"
	"github.com/abdo75/Schlass/internal/httputil"
	"github.com/abdo75/Schlass/internal/mail"
	"github.com/abdo75/Schlass/internal/users"
)

type Handler struct {
	pool           *pgxpool.Pool
	instanceConfig *instanceconfig.Service
	auditStore     audit.Logger
	encryptionKey  []byte
}

func NewHandler(pool *pgxpool.Pool, instanceConfig *instanceconfig.Service, auditStore audit.Logger, encryptionKey []byte) *Handler {
	return &Handler{pool: pool, instanceConfig: instanceConfig, auditStore: auditStore, encryptionKey: encryptionKey}
}

func (h *Handler) GetAll(w http.ResponseWriter, r *http.Request) {
	snap, err := h.instanceConfig.Settings(r.Context(), h.pool)
	if err != nil {
		slog.Error("settings.GetAll", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, snap)
}

func (h *Handler) PatchGeneral(w http.ResponseWriter, r *http.Request) {
	actor, ok := users.CurrentUser(r.Context())
	if !ok {
		httputil.WriteError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}
	ip := extractClientIP(r)

	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var in GeneralSettings
	if err := dec.Decode(&in); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body.")
		return
	}
	if err := ValidateGeneralSettings(&in); err != nil {
		writeValidationError(w, err)
		return
	}
	newName := strings.TrimSpace(in.InstanceName)

	oldName, err := h.instanceConfig.InstanceName(r.Context(), h.pool)
	if err != nil {
		slog.Error("settings.PatchGeneral: get old", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if newName == oldName {
		snap, _ := h.instanceConfig.Settings(r.Context(), h.pool)
		httputil.WriteJSON(w, http.StatusOK, snap.General)
		return
	}

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("settings.PatchGeneral: begin tx", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	if err := h.instanceConfig.SetInstanceName(r.Context(), tx, newName); err != nil {
		slog.Error("settings.PatchGeneral: set", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.auditStore.Log(r.Context(), tx, audit.Entry{
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
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("settings.PatchGeneral: commit", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	snap, _ := h.instanceConfig.Settings(r.Context(), h.pool)
	httputil.WriteJSON(w, http.StatusOK, snap.General)
}

func (h *Handler) PatchSecurity(w http.ResponseWriter, r *http.Request) {
	actor, ok := users.CurrentUser(r.Context())
	if !ok {
		httputil.WriteError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}
	ip := extractClientIP(r)

	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var in SecuritySettings
	if err := dec.Decode(&in); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body.")
		return
	}
	if err := ValidateSecuritySettings(&in); err != nil {
		writeValidationError(w, err)
		return
	}

	pre, err := h.instanceConfig.Settings(r.Context(), h.pool)
	if err != nil {
		slog.Error("settings.PatchSecurity: snapshot", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

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
		httputil.WriteJSON(w, http.StatusOK, pre.Security)
		return
	}

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("settings.PatchSecurity: begin tx", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	for _, c := range changes {
		if err := c.write(r.Context(), tx); err != nil {
			slog.Error("settings.PatchSecurity: write", "error", err, "key", c.key)
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		if err := h.auditStore.Log(r.Context(), tx, audit.Entry{
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
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("settings.PatchSecurity: commit", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	snap, _ := h.instanceConfig.Settings(r.Context(), h.pool)
	httputil.WriteJSON(w, http.StatusOK, snap.Security)
}

func (h *Handler) PatchTokens(w http.ResponseWriter, r *http.Request) {
	actor, ok := users.CurrentUser(r.Context())
	if !ok {
		httputil.WriteError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}
	ip := extractClientIP(r)

	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var in TokenSettings
	if err := dec.Decode(&in); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body.")
		return
	}
	if err := ValidateTokenSettings(&in); err != nil {
		writeValidationError(w, err)
		return
	}

	pre, err := h.instanceConfig.Settings(r.Context(), h.pool)
	if err != nil {
		slog.Error("settings.PatchTokens: snapshot", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
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
		httputil.WriteJSON(w, http.StatusOK, pre.Tokens)
		return
	}

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("settings.PatchTokens: begin tx", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	for _, c := range changes {
		if err := c.write(r.Context(), tx); err != nil {
			slog.Error("settings.PatchTokens: write", "error", err, "key", c.key)
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		if err := h.auditStore.Log(r.Context(), tx, audit.Entry{
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
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("settings.PatchTokens: commit", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	snap, _ := h.instanceConfig.Settings(r.Context(), h.pool)
	httputil.WriteJSON(w, http.StatusOK, snap.Tokens)
}

func (h *Handler) PatchAuditLog(w http.ResponseWriter, r *http.Request) {
	actor, ok := users.CurrentUser(r.Context())
	if !ok {
		httputil.WriteError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}
	ip := extractClientIP(r)

	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var in AuditLogSettings
	if err := dec.Decode(&in); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body.")
		return
	}
	if err := ValidateAuditLogSettings(&in); err != nil {
		writeValidationError(w, err)
		return
	}

	pre, err := h.instanceConfig.Settings(r.Context(), h.pool)
	if err != nil {
		slog.Error("settings.PatchAuditLog: snapshot", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	type change struct {
		key   string
		oldV  any
		newV  any
		write func(ctx context.Context, tx pgx.Tx) error
	}
	var changes []change
	if in.ViewLoggingEnabled != nil && *in.ViewLoggingEnabled != pre.AuditLog.ViewLoggingEnabled {
		v := *in.ViewLoggingEnabled
		changes = append(changes, change{"audit_view_logging_enabled", pre.AuditLog.ViewLoggingEnabled, v, func(ctx context.Context, tx pgx.Tx) error {
			return h.instanceConfig.SetBool(ctx, tx, "audit_view_logging_enabled", v)
		}})
	}
	if in.ExportMaxRows != nil && *in.ExportMaxRows != pre.AuditLog.ExportMaxRows {
		v := *in.ExportMaxRows
		changes = append(changes, change{"audit_export_max_rows", pre.AuditLog.ExportMaxRows, v, func(ctx context.Context, tx pgx.Tx) error {
			return h.instanceConfig.SetInt(ctx, tx, "audit_export_max_rows", v)
		}})
	}

	if len(changes) == 0 {
		httputil.WriteJSON(w, http.StatusOK, pre.AuditLog)
		return
	}

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("settings.PatchAuditLog: begin tx", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	for _, c := range changes {
		if err := c.write(r.Context(), tx); err != nil {
			slog.Error("settings.PatchAuditLog: write", "error", err, "key", c.key)
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		if err := h.auditStore.Log(r.Context(), tx, audit.Entry{
			EventType:  "config." + c.key + ".changed",
			ActorID:    &actor.ID,
			ActorEmail: actor.Email,
			TargetType: "instance_config",
			TargetID:   c.key,
			IPAddress:  ip,
			Outcome:    "success",
			Metadata:   map[string]any{"old_value": c.oldV, "new_value": c.newV},
		}); err != nil {
			slog.Error("settings.PatchAuditLog: audit", "error", err, "key", c.key)
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("settings.PatchAuditLog: commit", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	snap, _ := h.instanceConfig.Settings(r.Context(), h.pool)
	httputil.WriteJSON(w, http.StatusOK, snap.AuditLog)
}

// PatchEmail: password semantic is empty = keep current, non-empty =
// replace + re-encrypt via SetEncryptedValue (AES-256-GCM). Audit metadata
// on smtp_password is {"changed": true} ONLY — never plaintext or
// ciphertext. TestPatchEmail_KeepCurrentPasswordOnEmpty grep-asserts this
// and fails loudly on regression.
func (h *Handler) PatchEmail(w http.ResponseWriter, r *http.Request) {
	actor, ok := users.CurrentUser(r.Context())
	if !ok {
		httputil.WriteError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}
	ip := extractClientIP(r)

	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var in EmailSettings
	if err := dec.Decode(&in); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body.")
		return
	}
	if err := ValidateEmailSettings(&in); err != nil {
		writeValidationError(w, err)
		return
	}

	pre, err := h.instanceConfig.Settings(r.Context(), h.pool)
	if err != nil {
		slog.Error("settings.PatchEmail: snapshot", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
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
		httputil.WriteJSON(w, http.StatusOK, pre.Email)
		return
	}

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("settings.PatchEmail: begin tx", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	for _, c := range changes {
		if err := c.write(r.Context(), tx); err != nil {
			slog.Error("settings.PatchEmail: write", "error", err, "key", c.key)
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		if err := h.auditStore.Log(r.Context(), tx, audit.Entry{
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
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("settings.PatchEmail: commit", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	snap, _ := h.instanceConfig.Settings(r.Context(), h.pool)
	httputil.WriteJSON(w, http.StatusOK, snap.Email)
}

// categorizeSMTPError maps mail errors to stable client-facing codes. The
// raw err.Error() may embed DNS names, IPs, or TLS chain details — safe to
// log but not to surface on any UI an XSS or admin-session theft could scrape.
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

func (h *Handler) TestEmail(w http.ResponseWriter, r *http.Request) {
	actor, ok := users.CurrentUser(r.Context())
	if !ok {
		httputil.WriteError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}

	sender, err := mail.NewSenderFromConfig(r.Context(), h.instanceConfig, h.pool)
	if err != nil {
		if errors.Is(err, mail.ErrSMTPConfigIncomplete) {
			httputil.WriteError(w, http.StatusBadRequest, "SMTP_CONFIG_INCOMPLETE", "Complete and save the SMTP configuration before testing.")
			return
		}
		slog.Error("settings.TestEmail: new sender", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	instanceName, _ := h.instanceConfig.InstanceName(r.Context(), h.pool)
	if instanceName == "" {
		instanceName = "Schlass"
	}
	if err := sender.TestConnection(r.Context(), actor.Email, instanceName); err != nil {
		slog.Error("settings.TestEmail: send", "error", err, "actor", actor.Email)
		code, msg := categorizeSMTPError(err)
		httputil.WriteError(w, http.StatusBadGateway, code, msg)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{"delivered_at": time.Now().UTC().Format(time.RFC3339)})
}

func writeValidationError(w http.ResponseWriter, err error) {
	var ve *apierrors.ValidationError
	if errors.As(err, &ve) {
		code := ve.Code
		if code == "" {
			code = "VALIDATION_ERROR"
		}
		httputil.WriteError(w, http.StatusBadRequest, code, ve.Error())
		return
	}
	httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
}

func extractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
