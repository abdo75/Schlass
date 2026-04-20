package handler

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdo75/Schlass/internal/config"
	"github.com/abdo75/Schlass/internal/crypto"
	"github.com/abdo75/Schlass/internal/model"
	"github.com/abdo75/Schlass/internal/store"
)

type SetupHandler struct {
	pool          *pgxpool.Pool
	configService *config.ConfigService
	configStore   *store.ConfigStore
	userStore     *store.UserStore
	auditStore    AuditLogger
	hibpChecker   *crypto.HIBPChecker
}

func NewSetupHandler(
	pool *pgxpool.Pool,
	configService *config.ConfigService,
	configStore *store.ConfigStore,
	userStore *store.UserStore,
	auditStore AuditLogger,
	hibpChecker *crypto.HIBPChecker,
) *SetupHandler {
	return &SetupHandler{
		pool:          pool,
		configService: configService,
		configStore:   configStore,
		userStore:     userStore,
		auditStore:    auditStore,
		hibpChecker:   hibpChecker,
	}
}

func (h *SetupHandler) GetSetup(w http.ResponseWriter, r *http.Request) {
	complete, err := h.configService.IsSetupComplete(r.Context(), h.pool)
	if err != nil {
		slog.Error("failed to check setup state", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if complete {
		writeError(w, http.StatusNotFound, "SETUP_ALREADY_COMPLETE", "Setup has already been completed.")
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"setup_required": true})
}

func (h *SetupHandler) PostSetup(w http.ResponseWriter, r *http.Request) {
	complete, err := h.configService.IsSetupComplete(r.Context(), h.pool)
	if err != nil {
		slog.Error("failed to check setup state", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if complete {
		writeError(w, http.StatusNotFound, "SETUP_ALREADY_COMPLETE", "Setup has already been completed.")
		return
	}

	var req model.SetupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body.")
		return
	}

	policy, err := h.configService.GetPasswordPolicy(r.Context(), h.pool)
	if err != nil {
		slog.Error("failed to get password policy", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := req.Validate(policy); err != nil {
		code := "VALIDATION_ERROR"
		var policyErr *model.PasswordPolicyError
		if errors.As(err, &policyErr) {
			code = "PASSWORD_POLICY_VIOLATION"
		}
		writeError(w, http.StatusBadRequest, code, err.Error())
		return
	}

	// HIBP breach-corpus check (NIST SP 800-63B-4 §3.1.1.2). Fail-open
	// on network error — HIBP outages must not block password changes.
	if pwned, hibpErr := h.hibpChecker.IsPwned(r.Context(), req.Password); hibpErr != nil {
		slog.Warn("password_breach_check: hibp unavailable", "error", hibpErr)
	} else if pwned {
		writeError(w, http.StatusBadRequest, "PASSWORD_BREACHED",
			"This password has appeared in a known data breach. Choose a different one.")
		return
	}

	passwordHash, err := crypto.HashPassword(req.Password)
	if err != nil {
		slog.Error("failed to hash password", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("failed to begin transaction", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }() // error is non-actionable after a successful Commit (pgx returns ErrTxClosed)

	// Canonicalize email to lowercase before storage. The DB also enforces
	// this via a functional UNIQUE INDEX on LOWER(email) (migration 000012);
	// the handler boundary is the primary chokepoint, the index is the
	// defense-in-depth backstop for any path that bypasses the handler.
	req.Email = strings.ToLower(req.Email)

	userID, err := h.userStore.Create(r.Context(), tx, req.Email, passwordHash, "super_admin", false)
	if err != nil {
		slog.Error("failed to create admin user", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := h.configService.SetSetupComplete(r.Context(), tx); err != nil {
		slog.Error("failed to set setup_complete", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.configService.SetInstanceName(r.Context(), tx, req.InstanceName); err != nil {
		slog.Error("failed to set instance_name", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
		EventType:  "setup.completed",
		ActorID:    &userID,
		ActorEmail: req.Email,
		TargetType: "instance",
		TargetID:   "setup",
		IPAddress:  extractClientIP(r),
		Outcome:    "success",
		Metadata:   map[string]any{"instance_name": req.InstanceName},
	}); err != nil {
		slog.Error("failed to write audit log", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("failed to commit transaction", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"redirect": "/login"})
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
