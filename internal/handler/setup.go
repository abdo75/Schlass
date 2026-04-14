package handler

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/schlass/schlass/internal/config"
	"github.com/schlass/schlass/internal/crypto"
	"github.com/schlass/schlass/internal/model"
	"github.com/schlass/schlass/internal/store"
)

type SetupHandler struct {
	pool          *pgxpool.Pool
	configService *config.ConfigService
	configStore   *store.ConfigStore
	userStore     *store.UserStore
	auditStore    *store.AuditStore
}

func NewSetupHandler(
	pool *pgxpool.Pool,
	configService *config.ConfigService,
	configStore *store.ConfigStore,
	userStore *store.UserStore,
	auditStore *store.AuditStore,
) *SetupHandler {
	return &SetupHandler{
		pool:          pool,
		configService: configService,
		configStore:   configStore,
		userStore:     userStore,
		auditStore:    auditStore,
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
	defer tx.Rollback(r.Context())

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
