// Package handler — users.go hosts the UsersHandler for /api/users/* admin
// endpoints. Task 5 of Sprint 3 scaffolds the struct, shared helpers, and 11
// route stubs returning 501 NOT_IMPLEMENTED. Subsequent tasks (T6–T11) replace
// the stubs with real implementations.
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdo75/Schlass/internal/config"
	"github.com/abdo75/Schlass/internal/crypto"
	"github.com/abdo75/Schlass/internal/middleware"
	"github.com/abdo75/Schlass/internal/model"
	"github.com/abdo75/Schlass/internal/session"
	"github.com/abdo75/Schlass/internal/store"
)

// UsersHandler serves the admin-only /api/users/* endpoints. Constructed in
// internal/server/router.go and wrapped with middleware.Auth +
// middleware.RequireRole("super_admin") at wiring time.
type UsersHandler struct {
	pool          *pgxpool.Pool
	userStore     *store.UserStore
	auditStore    AuditLogger
	sessionStore  session.Store
	configService *config.ConfigService
}

// NewUsersHandler wires the dependencies UsersHandler needs. All fields are
// required; the constructor is intentionally dumb — validation happens at
// startup in main.go where the pool/stores are constructed.
func NewUsersHandler(
	pool *pgxpool.Pool,
	userStore *store.UserStore,
	auditStore AuditLogger,
	sessionStore session.Store,
	configService *config.ConfigService,
) *UsersHandler {
	return &UsersHandler{
		pool:          pool,
		userStore:     userStore,
		auditStore:    auditStore,
		sessionStore:  sessionStore,
		configService: configService,
	}
}

// pathParam is a tiny wrapper over http.Request.PathValue so callers read
// naturally (`pathParam(r, "id")`). Mostly cosmetic — keeps the stdlib
// net/http routing pattern out of handler method bodies.
//
//nolint:unused // used by Tasks 6–11 which land after Task 5
func pathParam(r *http.Request, name string) string {
	return r.PathValue(name)
}

// parseUserID pulls the `:id` path segment, parses it as a UUID, and writes a
// 400 VALIDATION_ERROR if the parse fails. Returns (id, true) on success and
// (uuid.Nil, false) on failure — callers should return immediately on false.
//
//nolint:unused // used by Tasks 6–11 which land after Task 5
func parseUserID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	raw := pathParam(r, "id")
	id, err := uuid.Parse(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid user id.")
		return uuid.Nil, false
	}
	return id, true
}

// rejectSelfOp writes a 400 CANNOT_OPERATE_ON_SELF if the authenticated user's
// ID equals targetID and returns true. Callers use the bool to short-circuit:
//
//	if h.rejectSelfOp(w, r, id) { return }
//
// Prevents an admin from disabling, resetting, or deleting their own account
// via the admin API. If no user is in context (wiring bug), we also reject so
// we never silently allow a self-op.
//
//nolint:unused // used by Tasks 6–11 which land after Task 5
func (h *UsersHandler) rejectSelfOp(w http.ResponseWriter, r *http.Request, targetID uuid.UUID) bool {
	current, ok := middleware.CurrentUser(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return true
	}
	if current.ID == targetID {
		writeError(w, http.StatusBadRequest, "CANNOT_OPERATE_ON_SELF", "You cannot perform this action on your own account.")
		return true
	}
	return false
}

// lockSuperAdminsForUpdate takes a row-level lock on every super_admin row so
// the current transaction can safely count remaining active admins without a
// concurrent disable/delete changing the answer. Must be called inside a tx.
//
//nolint:unused // used by Tasks 6–11 which land after Task 5
func lockSuperAdminsForUpdate(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `SELECT id FROM users WHERE role = 'super_admin' FOR UPDATE`)
	return err
}

// remainingActiveSuperAdmins counts super_admins that remain active (not
// disabled, not deleted) after whatever change the surrounding transaction has
// already staged. Must be called after lockSuperAdminsForUpdate.
//
//nolint:unused // used by Tasks 6–11 which land after Task 5
func remainingActiveSuperAdmins(ctx context.Context, tx pgx.Tx) (int, error) {
	var n int
	err := tx.QueryRow(ctx,
		`SELECT COUNT(*) FROM users
		 WHERE role = 'super_admin'
		   AND status = 'active'`,
	).Scan(&n)
	return n, err
}

// enforceLastAdminLockout counts remaining active super_admins and, if zero,
// writes a 400 LAST_ADMIN_LOCKOUT and returns true so the caller can abort.
// Must be called inside the same tx that already applied the staged change
// (disable/delete/role-demote) — this is the compliance gate that prevents an
// admin from locking everyone out of the system.
//
//nolint:unused // used by Tasks 6–11 which land after Task 5
func (h *UsersHandler) enforceLastAdminLockout(ctx context.Context, tx pgx.Tx, w http.ResponseWriter) bool {
	n, err := remainingActiveSuperAdmins(ctx, tx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return true
	}
	if n == 0 {
		writeError(w, http.StatusBadRequest, "LAST_ADMIN_LOCKOUT", "Cannot leave the system without an active super_admin.")
		return true
	}
	return false
}

// uniqueViolationAsEmailConflict inspects err for a pgx SQLSTATE 23505
// unique-violation (the only unique constraint on users is the email column)
// and, if matched, writes 409 EMAIL_ALREADY_EXISTS and returns true. Any other
// error (or nil) returns false and the caller handles it.
func uniqueViolationAsEmailConflict(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		writeError(w, http.StatusConflict, "EMAIL_ALREADY_EXISTS", "A user with that email already exists.")
		return true
	}
	return false
}

// --- Stub methods — 501 NOT_IMPLEMENTED until Tasks 6–11 replace them. ---

type createUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

// List handles GET /api/users.
func (h *UsersHandler) List(w http.ResponseWriter, r *http.Request) {
	limit := 50
	offset := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 200 {
		limit = 200
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	emailSearch := r.URL.Query().Get("email")

	result, err := h.userStore.List(r.Context(), h.pool, store.ListUsersParams{
		Limit:       limit,
		Offset:      offset,
		EmailSearch: emailSearch,
	})
	if err != nil {
		slog.Error("users.List failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	// Serialize users (hide password_hash from response).
	usersOut := make([]map[string]any, 0, len(result.Users))
	for _, u := range result.Users {
		usersOut = append(usersOut, userDTO(u))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"users":  usersOut,
		"total":  result.Total,
		"limit":  limit,
		"offset": offset,
	})
}

// userDTO returns the response shape — everything except the password hash.
func userDTO(u *store.User) map[string]any {
	return map[string]any{
		"id":                    u.ID.String(),
		"email":                 u.Email,
		"role":                  u.Role,
		"status":                u.Status,
		"force_password_change": u.ForcePasswordChange,
		"created_at":            u.CreatedAt,
		"updated_at":            u.UpdatedAt,
	}
}

// Create handles POST /api/users.
func (h *UsersHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body.")
		return
	}
	if req.Email == "" || !strings.Contains(req.Email, "@") {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid email.")
		return
	}
	if req.Role != "super_admin" && req.Role != "user" {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "role must be 'super_admin' or 'user'.")
		return
	}

	// Password policy check.
	policy, err := h.configService.GetPasswordPolicy(r.Context(), h.pool)
	if err != nil {
		slog.Error("load password policy", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := model.ValidatePassword(req.Password, policy); err != nil {
		var policyErr *model.PasswordPolicyError
		if errors.As(err, &policyErr) {
			writeError(w, http.StatusBadRequest, "PASSWORD_POLICY_VIOLATION", err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	hash, err := crypto.HashPassword(req.Password)
	if err != nil {
		slog.Error("hash password", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	current, ok := middleware.CurrentUser(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}
	ip := extractClientIP(r)

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("begin tx", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	newID, err := h.userStore.Create(r.Context(), tx, req.Email, hash, req.Role, true)
	if err != nil {
		if uniqueViolationAsEmailConflict(w, err) {
			return
		}
		slog.Error("create user", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if auditErr := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
		EventType:  "user.created",
		ActorID:    &current.ID,
		ActorEmail: current.Email,
		TargetType: "user",
		TargetID:   newID.String(),
		IPAddress:  ip,
		Outcome:    "success",
		Metadata:   map[string]any{"email": req.Email, "role": req.Role},
	}); auditErr != nil {
		slog.Error("audit user.created", "error", auditErr)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("commit create user", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	// Fetch the freshly-created row for the response.
	fresh, err := h.userStore.GetByID(r.Context(), h.pool, newID)
	if err != nil {
		slog.Error("fetch new user", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"user": userDTO(fresh)})
}

func (h *UsersHandler) Get(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "coming in Task 7")
}

func (h *UsersHandler) Update(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "coming in Task 7")
}

func (h *UsersHandler) Disable(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "coming in Task 8")
}

func (h *UsersHandler) Enable(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "coming in Task 8")
}

func (h *UsersHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "coming in Task 9")
}

func (h *UsersHandler) Delete(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "coming in Task 10")
}

func (h *UsersHandler) ListSessions(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "coming in Task 11")
}

func (h *UsersHandler) TerminateAllSessions(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "coming in Task 11")
}

func (h *UsersHandler) TerminateSession(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "coming in Task 11")
}
