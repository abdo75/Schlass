// Package server handles the one-time first-boot wizard: GET /api/setup reports
// whether setup is still required; POST /api/setup creates the initial
// super_admin account and marks the instance configured.
package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdo75/Schlass/internal/apierrors"
	"github.com/abdo75/Schlass/internal/audit"
	"github.com/abdo75/Schlass/internal/crypto"
	"github.com/abdo75/Schlass/internal/httputil"
	"github.com/abdo75/Schlass/internal/instanceconfig"
	"github.com/abdo75/Schlass/internal/users"
)

type SetupHandler struct {
	pool           *pgxpool.Pool
	instanceConfig *instanceconfig.Service
	configStore    *instanceconfig.Store
	userStore      *users.Store
	auditStore     audit.Logger
	hibpChecker    *crypto.HIBPChecker
}

func NewSetupHandler(
	pool *pgxpool.Pool,
	instanceConfig *instanceconfig.Service,
	configStore *instanceconfig.Store,
	userStore *users.Store,
	auditStore audit.Logger,
	hibpChecker *crypto.HIBPChecker,
) *SetupHandler {
	return &SetupHandler{
		pool:           pool,
		instanceConfig: instanceConfig,
		configStore:    configStore,
		userStore:      userStore,
		auditStore:     auditStore,
		hibpChecker:    hibpChecker,
	}
}

func (h *SetupHandler) GetSetup(w http.ResponseWriter, r *http.Request) {
	complete, err := h.instanceConfig.IsSetupComplete(r.Context(), h.pool)
	if err != nil {
		slog.Error("failed to check setup state", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if complete {
		httputil.WriteError(w, http.StatusNotFound, "SETUP_ALREADY_COMPLETE", "Setup has already been completed.")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]bool{"setup_required": true})
}

func (h *SetupHandler) PostSetup(w http.ResponseWriter, r *http.Request) {
	complete, err := h.instanceConfig.IsSetupComplete(r.Context(), h.pool)
	if err != nil {
		slog.Error("failed to check setup state", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if complete {
		httputil.WriteError(w, http.StatusNotFound, "SETUP_ALREADY_COMPLETE", "Setup has already been completed.")
		return
	}

	var req Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body.")
		return
	}

	policy, err := h.instanceConfig.PasswordPolicy(r.Context(), h.pool)
	if err != nil {
		slog.Error("failed to get password policy", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := req.Validate(policy); err != nil {
		code := "VALIDATION_ERROR"
		var policyErr *apierrors.PasswordPolicyError
		if errors.As(err, &policyErr) {
			code = "PASSWORD_POLICY_VIOLATION"
		}
		httputil.WriteError(w, http.StatusBadRequest, code, err.Error())
		return
	}

	// HIBP breach-corpus check (NIST SP 800-63B-4 §3.1.1.2). Fail-open on
	// network error — HIBP outages must not block password changes.
	if pwned, hibpErr := h.hibpChecker.IsPwned(r.Context(), req.Password); hibpErr != nil {
		slog.Warn("password_breach_check: hibp unavailable", "error", hibpErr)
	} else if pwned {
		httputil.WriteError(w, http.StatusBadRequest, "PASSWORD_BREACHED",
			"This password has appeared in a known data breach. Choose a different one.")
		return
	}

	passwordHash, err := crypto.HashPassword(req.Password)
	if err != nil {
		slog.Error("failed to hash password", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("failed to begin transaction", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	// email canonicalized lowercase; DB also enforces via UNIQUE(LOWER(email))
	// in migration 000012 as defense-in-depth.
	req.Email = strings.ToLower(req.Email)

	userID, err := h.userStore.Create(r.Context(), tx, req.Email, passwordHash, "super_admin", false)
	if err != nil {
		slog.Error("failed to create admin user", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	// Granular per NIST 800-53 AU-3 / PCI 10.2.1.5: provisioning of the first
	// admin is its own forensic record, separate from the setup roll-up.
	userIDStr := userID.String()
	if err := h.auditStore.Emit(r.Context(), tx, audit.Event{
		EventType:  "user.created",
		ActorID:    &userID,
		ActorEmail: req.Email,
		TargetType: "user",
		TargetID:   userIDStr,
		IPAddress:  extractClientIP(r),
		Outcome:    "success",
		// REQ-AUD-011 (M2): no plaintext email in metadata.
		Metadata: map[string]any{"role": "super_admin"},
	}); err != nil {
		slog.Error("failed to write audit log", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := h.instanceConfig.SetSetupComplete(r.Context(), tx); err != nil {
		slog.Error("failed to set setup_complete", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.instanceConfig.SetInstanceName(r.Context(), tx, req.InstanceName); err != nil {
		slog.Error("failed to set instance_name", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := h.auditStore.Emit(r.Context(), tx, audit.Event{
		EventType:  "setup.completed",
		ActorID:    &userID,
		ActorEmail: req.Email,
		TargetType: "instance",
		IPAddress:  extractClientIP(r),
		Outcome:    "success",
		Metadata:   map[string]any{"instance_name": req.InstanceName},
	}); err != nil {
		slog.Error("failed to write audit log", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("failed to commit transaction", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"redirect": "/login"})
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
