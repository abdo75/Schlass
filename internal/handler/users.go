// Package handler — users.go hosts the UsersHandler for /api/users/* admin
// endpoints. Task 5 of Sprint 3 scaffolds the struct, shared helpers, and 11
// route stubs returning 501 NOT_IMPLEMENTED. Subsequent tasks (T6–T11) replace
// the stubs with real implementations.
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdo75/Schlass/internal/config"
	"github.com/abdo75/Schlass/internal/crypto"
	"github.com/abdo75/Schlass/internal/middleware"
	"github.com/abdo75/Schlass/internal/session"
	"github.com/abdo75/Schlass/internal/store"
)

// UsersHandler serves the admin-only /api/users/* endpoints. Constructed in
// internal/server/router.go and wrapped with middleware.Auth + a per-route
// middleware.RequirePermission gate at wiring time.
type UsersHandler struct {
	pool              *pgxpool.Pool
	userStore         *store.UserStore
	auditStore        AuditLogger
	sessionStore      session.Store
	configService     *config.ConfigService
	recoveryCodeStore *store.RecoveryCodeStore
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
	recoveryCodeStore *store.RecoveryCodeStore,
) *UsersHandler {
	return &UsersHandler{
		pool:              pool,
		userStore:         userStore,
		auditStore:        auditStore,
		sessionStore:      sessionStore,
		configService:     configService,
		recoveryCodeStore: recoveryCodeStore,
	}
}

// pathParam is a tiny wrapper over http.Request.PathValue so callers read
// naturally (`pathParam(r, "id")`). Mostly cosmetic — keeps the stdlib
// net/http routing pattern out of handler method bodies.
func pathParam(r *http.Request, name string) string {
	return r.PathValue(name)
}

// parseUserID pulls the `:id` path segment, parses it as a UUID, and writes a
// 400 VALIDATION_ERROR if the parse fails. Returns (id, true) on success and
// (uuid.Nil, false) on failure — callers should return immediately on false.
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
func lockSuperAdminsForUpdate(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `SELECT id FROM users WHERE role = 'super_admin' FOR UPDATE`)
	return err
}

// remainingActiveSuperAdmins counts super_admins that remain active (not
// disabled, not deleted) after whatever change the surrounding transaction has
// already staged. Must be called after lockSuperAdminsForUpdate.
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
	Email string `json:"email"`
	Role  string `json:"role"`
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
	req.Email = strings.ToLower(req.Email)
	if req.Role != "super_admin" && req.Role != "user" {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "role must be 'super_admin' or 'user'.")
		return
	}

	tempPassword, err := crypto.GenerateTemporaryPassword()
	if err != nil {
		slog.Error("generate temporary password", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	hash, err := crypto.HashPassword(tempPassword)
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
	writeJSON(w, http.StatusCreated, map[string]any{
		"user":               userDTO(fresh),
		"temporary_password": tempPassword,
	})
}

// Get handles GET /api/users/:id. Returns the user DTO plus the list of
// active sessions (each carrying its opaque token so the admin UI can issue
// per-device terminate calls). If the session store is temporarily unavailable
// we degrade gracefully: log a WARN and return the user DTO with a nil
// sessions array rather than failing the whole request.
func (h *UsersHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUserID(w, r)
	if !ok {
		return
	}

	user, err := h.userStore.GetByID(r.Context(), h.pool, id)
	if err != nil {
		if errors.Is(err, store.ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "USER_NOT_FOUND", "User not found.")
			return
		}
		slog.Error("users.Get: fetch user", "error", err, "user_id", id) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	sessions, err := h.sessionStore.ListByUser(r.Context(), id.String())
	if err != nil {
		slog.Warn("users.Get: list sessions degraded", "error", err, "user_id", id) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
		sessions = nil
	}

	sessionsOut := make([]map[string]any, 0, len(sessions))
	for _, s := range sessions {
		sessionsOut = append(sessionsOut, map[string]any{
			"token":        s.Token,
			"created_at":   s.CreatedAt,
			"last_seen_at": s.LastSeenAt,
			"ip_address":   s.IPAddress,
			"user_agent":   s.UserAgent,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"user":     userDTO(user),
		"sessions": sessionsOut,
	})
}

// updateUserRequest — PATCH body. Both fields optional; at least one required.
type updateUserRequest struct {
	Email *string `json:"email,omitempty"`
	Role  *string `json:"role,omitempty"`
}

// Update handles PATCH /api/users/:id. Supports partial updates of email and
// role. Self-op guard only fires on role change (self-email-update is allowed).
// Role-demotion of a super_admin triggers the last-admin lockout guard inside
// the transaction.
func (h *UsersHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUserID(w, r)
	if !ok {
		return
	}

	var req updateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body.")
		return
	}
	if req.Email == nil && req.Role == nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "At least one of email or role is required.")
		return
	}
	if req.Email != nil {
		if *req.Email == "" || !strings.Contains(*req.Email, "@") {
			writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid email.")
			return
		}
		lower := strings.ToLower(*req.Email)
		req.Email = &lower
	}
	if req.Role != nil {
		if *req.Role != "super_admin" && *req.Role != "user" {
			writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "role must be 'super_admin' or 'user'.")
			return
		}
	}

	// Self-op guard — only on role change. An admin is allowed to update
	// their own email, but must not demote (or even re-affirm) their own role
	// via this endpoint.
	if req.Role != nil && h.rejectSelfOp(w, r, id) {
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
		slog.Error("users.Update: begin tx", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	existing, err := h.userStore.GetByID(r.Context(), tx, id)
	if err != nil {
		if errors.Is(err, store.ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "USER_NOT_FOUND", "User not found.")
			return
		}
		slog.Error("users.Update: fetch existing", "error", err, "user_id", id) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	newEmail := existing.Email
	if req.Email != nil {
		newEmail = *req.Email
	}
	newRole := existing.Role
	if req.Role != nil {
		newRole = *req.Role
	}

	// If this change demotes a super_admin, lock the admin set so the
	// remaining-count check below is race-free.
	demoting := existing.Role == "super_admin" && newRole != "super_admin"
	if demoting {
		if err := lockSuperAdminsForUpdate(r.Context(), tx); err != nil {
			slog.Error("users.Update: lock super_admins", "error", err)
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
	}

	if err := h.userStore.Update(r.Context(), tx, id, newEmail, newRole); err != nil {
		if uniqueViolationAsEmailConflict(w, err) {
			return
		}
		if errors.Is(err, store.ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "USER_NOT_FOUND", "User not found.")
			return
		}
		slog.Error("users.Update: update", "error", err, "user_id", id) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if demoting && h.enforceLastAdminLockout(r.Context(), tx, w) {
		return
	}

	changed := map[string]any{}
	if req.Email != nil && *req.Email != existing.Email {
		changed["email"] = map[string]any{"from": existing.Email, "to": *req.Email}
	}
	if req.Role != nil && *req.Role != existing.Role {
		changed["role"] = map[string]any{"from": existing.Role, "to": *req.Role}
	}

	if auditErr := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
		EventType:  "user.updated",
		ActorID:    &current.ID,
		ActorEmail: current.Email,
		TargetType: "user",
		TargetID:   id.String(),
		IPAddress:  ip,
		Outcome:    "success",
		Metadata:   map[string]any{"changed_fields": changed},
	}); auditErr != nil {
		slog.Error("audit user.updated", "error", auditErr)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("users.Update: commit", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	fresh, err := h.userStore.GetByID(r.Context(), h.pool, id)
	if err != nil {
		slog.Error("users.Update: refetch", "error", err, "user_id", id) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": userDTO(fresh)})
}

// Disable handles POST /api/users/:id/disable. Sets the target user's status
// to 'disabled', writes a user.disabled audit row in the same tx, and — after
// a successful commit — best-effort destroys every active session the user
// has in Valkey. If the session revocation call fails we log a WARN and
// return success anyway: the auth middleware's disabled-user check will
// revoke stale sessions on next request, so the database state is the source
// of truth and the Valkey entries are just a cache.
//
// Guards:
//   - parseUserID: 400 VALIDATION_ERROR on bad UUID.
//   - rejectSelfOp: 400 CANNOT_OPERATE_ON_SELF — an admin must not disable
//     their own account via the admin API.
//   - lockSuperAdminsForUpdate + enforceLastAdminLockout: if the target is a
//     super_admin, serializes against concurrent destructive ops and aborts
//     with 400 LAST_ADMIN_LOCKOUT if disabling would leave zero active admins.
func (h *UsersHandler) Disable(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUserID(w, r)
	if !ok {
		return
	}
	if h.rejectSelfOp(w, r, id) {
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
		slog.Error("users.Disable: begin tx", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	// Lock the admin set up-front so the optional last-admin check below is
	// race-free. Cheap on a super_admin set of ~1–10 rows and harmless for
	// non-admin targets — we'd rather pay the tiny lock cost than branch.
	if err := lockSuperAdminsForUpdate(r.Context(), tx); err != nil {
		slog.Error("users.Disable: lock super_admins", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	existing, err := h.userStore.GetByID(r.Context(), tx, id)
	if err != nil {
		if errors.Is(err, store.ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "USER_NOT_FOUND", "User not found.")
			return
		}
		slog.Error("users.Disable: fetch existing", "error", err, "user_id", id) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := h.userStore.SetStatus(r.Context(), tx, id, "disabled"); err != nil {
		if errors.Is(err, store.ErrUserNotFound) {
			// Shouldn't happen — we just verified existence under lock — but
			// keep the branch so a race doesn't 500.
			writeError(w, http.StatusNotFound, "USER_NOT_FOUND", "User not found.")
			return
		}
		slog.Error("users.Disable: set status", "error", err, "user_id", id) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	// Last-admin guard — only meaningful when disabling a super_admin.
	if existing.Role == "super_admin" && h.enforceLastAdminLockout(r.Context(), tx, w) {
		return
	}

	if auditErr := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
		EventType:  "user.disabled",
		ActorID:    &current.ID,
		ActorEmail: current.Email,
		TargetType: "user",
		TargetID:   id.String(),
		IPAddress:  ip,
		Outcome:    "success",
		Metadata:   map[string]any{"email": existing.Email, "role": existing.Role},
	}); auditErr != nil {
		slog.Error("audit user.disabled", "error", auditErr)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("users.Disable: commit", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	// Post-commit, best-effort: nuke every active session for this user so
	// they're kicked out immediately. If Valkey is temporarily unreachable we
	// log a WARN and return success — the auth middleware's disabled-user
	// check (Sprint 2) rejects stale sessions on next request, so the DB
	// row is the source of truth.
	if err := h.sessionStore.DeleteAllForUser(r.Context(), id.String()); err != nil {
		slog.Warn("users.Disable: session revocation degraded", "error", err, "user_id", id) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
	}

	w.WriteHeader(http.StatusNoContent)
}

// Enable handles POST /api/users/:id/enable. Sets the target user's status to
// 'active' and writes a user.enabled audit row in the same tx. No self-op
// guard (enabling yourself is a no-op) and no last-admin lockout check
// (enabling can only increase the active super_admin count, never decrease).
func (h *UsersHandler) Enable(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUserID(w, r)
	if !ok {
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
		slog.Error("users.Enable: begin tx", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	existing, err := h.userStore.GetByID(r.Context(), tx, id)
	if err != nil {
		if errors.Is(err, store.ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "USER_NOT_FOUND", "User not found.")
			return
		}
		slog.Error("users.Enable: fetch existing", "error", err, "user_id", id) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := h.userStore.SetStatus(r.Context(), tx, id, "active"); err != nil {
		if errors.Is(err, store.ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "USER_NOT_FOUND", "User not found.")
			return
		}
		slog.Error("users.Enable: set status", "error", err, "user_id", id) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if auditErr := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
		EventType:  "user.enabled",
		ActorID:    &current.ID,
		ActorEmail: current.Email,
		TargetType: "user",
		TargetID:   id.String(),
		IPAddress:  ip,
		Outcome:    "success",
		Metadata:   map[string]any{"email": existing.Email, "role": existing.Role},
	}); auditErr != nil {
		slog.Error("audit user.enabled", "error", auditErr)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("users.Enable: commit", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ResetPassword handles POST /api/users/:id/reset-password. The server
// generates a fresh temporary password (any client-supplied body is drained
// and discarded), hashes it, writes the update inside a tx with
// force_password_change=true so the user must change it on next login, audits
// the operation, commits, and then best-effort revokes every active session for
// the target so they're kicked out and must re-log in with the temp and walk
// the forced-change flow. Returns the plaintext temp password in a 200 body —
// that is the single place the plaintext ever appears.
func (h *UsersHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUserID(w, r)
	if !ok {
		return
	}

	if h.rejectSelfOp(w, r, id) {
		return
	}

	// Drain and discard any client-supplied body — the password is generated
	// server-side; whatever the client sends is irrelevant.
	_, _ = io.Copy(io.Discard, r.Body)

	tempPassword, err := crypto.GenerateTemporaryPassword()
	if err != nil {
		slog.Error("users.ResetPassword: generate temp password", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	hash, err := crypto.HashPassword(tempPassword)
	if err != nil {
		slog.Error("users.ResetPassword: hash password", "error", err)
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
		slog.Error("users.ResetPassword: begin tx", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	existing, err := h.userStore.GetByID(r.Context(), tx, id)
	if err != nil {
		if errors.Is(err, store.ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "USER_NOT_FOUND", "User not found.")
			return
		}
		slog.Error("users.ResetPassword: fetch existing", "error", err, "user_id", id) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := h.userStore.SetPasswordHash(r.Context(), tx, id, hash, true); err != nil {
		if errors.Is(err, store.ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "USER_NOT_FOUND", "User not found.")
			return
		}
		slog.Error("users.ResetPassword: set password hash", "error", err, "user_id", id) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if auditErr := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
		EventType:  "user.password_reset",
		ActorID:    &current.ID,
		ActorEmail: current.Email,
		TargetType: "user",
		TargetID:   id.String(),
		IPAddress:  ip,
		Outcome:    "success",
		Metadata:   map[string]any{"email": existing.Email},
	}); auditErr != nil {
		slog.Error("audit user.password_reset", "error", auditErr)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("users.ResetPassword: commit", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	// Post-commit, best-effort: kill every active session for this user so
	// they're forced to re-log in with the new temp and walk the
	// forced-change flow. DB state is the source of truth; if Valkey is
	// momentarily unavailable the auth middleware's force_password_change
	// check will still gate the next request.
	if err := h.sessionStore.DeleteAllForUser(r.Context(), id.String()); err != nil {
		slog.Warn("users.ResetPassword: session revocation degraded", "error", err, "user_id", id) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
	}

	writeJSON(w, http.StatusOK, map[string]any{"temporary_password": tempPassword})
}

// Delete handles DELETE /api/users/:id. Hard-deletes the target row from the
// users table. Relies on migration 000011 having dropped the audit_logs FK on
// actor_id: the audit trail must outlive the user row, so forensic queries
// can still reconstruct who did what long after the account is gone. Because
// actor_email is denormalized onto audit_logs and we write a user.deleted row
// that also captures the victim's email + role inline, the forensic story
// survives even without any FK-driven join back to the (now-absent) user.
//
// Guards:
//   - parseUserID: 400 VALIDATION_ERROR on bad UUID.
//   - rejectSelfOp: 400 CANNOT_OPERATE_ON_SELF — an admin must not hard-delete
//     their own account via the admin API.
//   - lockSuperAdminsForUpdate + enforceLastAdminLockout (only when the
//     target is a super_admin): serializes against concurrent destructive
//     ops and aborts with 400 LAST_ADMIN_LOCKOUT if deleting would leave
//     zero active super_admins.
//
// We read the victim row BEFORE running the DELETE so the audit metadata can
// carry deleted_user_email + deleted_user_role — otherwise the post-delete
// row would be gone and we'd have nothing to record.
func (h *UsersHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUserID(w, r)
	if !ok {
		return
	}
	if h.rejectSelfOp(w, r, id) {
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
		slog.Error("users.Delete: begin tx", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	// Lock the admin set up-front so the optional last-admin check below is
	// race-free. Cheap on a ~1–10 row super_admin set; mirrors Disable.
	if err := lockSuperAdminsForUpdate(r.Context(), tx); err != nil {
		slog.Error("users.Delete: lock super_admins", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	// Capture the victim row BEFORE the delete — the audit metadata needs
	// the email + role and the row is about to vanish.
	target, err := h.userStore.GetByID(r.Context(), tx, id)
	if err != nil {
		if errors.Is(err, store.ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "USER_NOT_FOUND", "User not found.")
			return
		}
		slog.Error("users.Delete: fetch target", "error", err, "user_id", id) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := h.userStore.Delete(r.Context(), tx, id); err != nil {
		if errors.Is(err, store.ErrUserNotFound) {
			// Shouldn't happen — we just verified existence under lock — but
			// keep the branch so a race doesn't 500.
			writeError(w, http.StatusNotFound, "USER_NOT_FOUND", "User not found.")
			return
		}
		slog.Error("users.Delete: delete", "error", err, "user_id", id) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	// Last-admin guard — only meaningful when deleting a super_admin.
	if target.Role == "super_admin" && h.enforceLastAdminLockout(r.Context(), tx, w) {
		return
	}

	if auditErr := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
		EventType:  "user.deleted",
		ActorID:    &current.ID,
		ActorEmail: current.Email,
		TargetType: "user",
		TargetID:   id.String(),
		IPAddress:  ip,
		Outcome:    "success",
		Metadata: map[string]any{
			"deleted_user_email": target.Email,
			"deleted_user_role":  target.Role,
		},
	}); auditErr != nil {
		slog.Error("audit user.deleted", "error", auditErr)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("users.Delete: commit", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	// Post-commit, best-effort: kill every active session for the (now
	// deleted) user in Valkey. DB is the source of truth; if Valkey is
	// temporarily unreachable, the auth middleware's user lookup will fail
	// on next request and revoke the stale session anyway.
	if err := h.sessionStore.DeleteAllForUser(r.Context(), id.String()); err != nil {
		slog.Warn("users.Delete: session revocation degraded", "error", err, "user_id", id) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
	}

	w.WriteHeader(http.StatusNoContent)
}

// ListSessions serves GET /api/users/:id/sessions. Standalone read path used
// by the admin UI to refresh its "active sessions" view without refetching
// the whole user record.
func (h *UsersHandler) ListSessions(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUserID(w, r)
	if !ok {
		return
	}

	sessions, err := h.sessionStore.ListByUser(r.Context(), id.String())
	if err != nil {
		slog.Error("users.ListSessions: session.ListByUser", "error", err, "user_id", id) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	out := make([]map[string]any, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, map[string]any{
			"token":        s.Token,
			"created_at":   s.CreatedAt,
			"last_seen_at": s.LastSeenAt,
			"ip_address":   s.IPAddress,
			"user_agent":   s.UserAgent,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

// TerminateAllSessions serves DELETE /api/users/:id/sessions. Nuclear
// force-terminate: kills every active session for the target user. Self-op
// is allowed — an admin can sign themselves out of all devices (standard
// IDP behavior: Okta, Auth0, Keycloak all permit this).
func (h *UsersHandler) TerminateAllSessions(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUserID(w, r)
	if !ok {
		return
	}

	current, _ := middleware.CurrentUser(r.Context())
	ip := extractClientIP(r)

	// Count before destruction for audit metadata. Best-effort: a Valkey
	// transport error here degrades the audit row's terminated_count to 0
	// but does not block the terminate flow — the DeleteAllForUser call
	// below is the source of truth for destruction.
	sessions, _ := h.sessionStore.ListByUser(r.Context(), id.String())
	beforeCount := len(sessions)

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("users.TerminateAllSessions: begin tx", "error", err) //nolint:gosec // G706
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	if err := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
		EventType:  "user.sessions_terminated",
		ActorID:    &current.ID,
		ActorEmail: current.Email,
		TargetType: "user",
		TargetID:   id.String(),
		IPAddress:  ip,
		Outcome:    "success",
		Metadata:   map[string]any{"terminated_count": beforeCount},
	}); err != nil {
		slog.Error("users.TerminateAllSessions: audit log", "error", err) //nolint:gosec // G706
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("users.TerminateAllSessions: commit", "error", err) //nolint:gosec // G706
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	// Post-commit, best-effort: wipe every session from Valkey. On transport
	// failure the auth middleware's per-request user lookup will still
	// effectively invalidate stale sessions on the next request (user
	// refetch), so the worst case is a brief window of staleness bounded
	// by the session TTL.
	if err := h.sessionStore.DeleteAllForUser(r.Context(), id.String()); err != nil {
		slog.Warn("users.TerminateAllSessions: session revocation degraded", "error", err, "user_id", id) //nolint:gosec // G706
	}

	w.WriteHeader(http.StatusNoContent)
}

// ResetMFA handles POST /api/users/{id}/reset-mfa — clears totp_* columns
// and deletes all recovery codes. Audit-in-tx. Self-op rejected (an admin
// who lost their authenticator needs another super_admin to reset them, or
// direct DB intervention if they're the only admin — same philosophy as
// last-admin-lockout).
func (h *UsersHandler) ResetMFA(w http.ResponseWriter, r *http.Request) {
	targetID, ok := parseUserID(w, r)
	if !ok {
		return
	}
	if h.rejectSelfOp(w, r, targetID) {
		return
	}

	acting, _ := middleware.CurrentUser(r.Context())

	target, err := h.userStore.GetByID(r.Context(), h.pool, targetID)
	if err != nil {
		if errors.Is(err, store.ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "USER_NOT_FOUND", "User not found.")
			return
		}
		slog.Error("reset-mfa: GetByID failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if target.TOTPEnrolledAt == nil {
		writeError(w, http.StatusBadRequest, "MFA_NOT_ENROLLED", "This user has not enrolled in MFA.")
		return
	}

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	deleted, err := h.recoveryCodeStore.DeleteAllForUser(r.Context(), tx, targetID)
	if err != nil {
		slog.Error("reset-mfa: DeleteAllForUser failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.userStore.ClearTOTP(r.Context(), tx, targetID); err != nil {
		slog.Error("reset-mfa: ClearTOTP failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	wasEnrolledAt := target.TOTPEnrolledAt.Format(time.RFC3339)
	if err := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
		EventType:  "mfa.reset",
		ActorID:    &acting.ID,
		ActorEmail: acting.Email,
		TargetType: "user",
		TargetID:   targetID.String(),
		IPAddress:  extractClientIP(r),
		Outcome:    "success",
		Metadata: map[string]any{
			"recovery_codes_burned": deleted,
			"was_enrolled_at":       wasEnrolledAt,
		},
	}); err != nil {
		slog.Error("reset-mfa: audit write failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("reset-mfa: Commit failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	// Post-tx: revoke all Valkey sessions for the target user — same pattern
	// as Sprint 3's users.Disable.
	if err := h.sessionStore.DeleteAllForUser(r.Context(), targetID.String()); err != nil {
		slog.Error("reset-mfa: DeleteAllForUser sessions failed", "error", err, "user_id", targetID.String()) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
		// Non-fatal — the audit row is committed, sessions expire on their
		// own if deletion fails.
	}

	updated, _ := h.userStore.GetByID(r.Context(), h.pool, targetID)
	writeJSON(w, http.StatusOK, map[string]any{"user": userDTO(updated)})
}

// TerminateSession serves DELETE /api/users/:id/sessions/:token. Per-device
// force-terminate. Unlike TerminateAllSessions, self-op is allowed here —
// killing a single specific session of your own (e.g. "sign out my other
// laptop") is a legitimate flow.
func (h *UsersHandler) TerminateSession(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUserID(w, r)
	if !ok {
		return
	}
	token := pathParam(r, "token")
	if token == "" {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Missing token.")
		return
	}

	current, _ := middleware.CurrentUser(r.Context())
	ip := extractClientIP(r)

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("users.TerminateSession: begin tx", "error", err) //nolint:gosec // G706
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	// Audit stores only the token prefix (first 8 chars) — not the full
	// credential. The full token is a secret and should not appear in
	// persistent storage outside the Valkey session key.
	tokenPrefix := token
	if len(tokenPrefix) > 8 {
		tokenPrefix = tokenPrefix[:8]
	}
	if err := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
		EventType:  "session.terminated",
		ActorID:    &current.ID,
		ActorEmail: current.Email,
		TargetType: "user",
		TargetID:   id.String(),
		IPAddress:  ip,
		Outcome:    "success",
		Metadata:   map[string]any{"token_prefix": tokenPrefix},
	}); err != nil {
		slog.Error("users.TerminateSession: audit log", "error", err) //nolint:gosec // G706
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("users.TerminateSession: commit", "error", err) //nolint:gosec // G706
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	// Post-commit, best-effort Valkey delete. Same rationale as
	// TerminateAllSessions: on transport failure the auth middleware will
	// still reject the session on next use via user-lookup, so at worst we
	// have a small staleness window bounded by the TTL.
	if err := h.sessionStore.Delete(r.Context(), id.String(), token); err != nil {
		slog.Warn("users.TerminateSession: session delete degraded", "error", err, "user_id", id) //nolint:gosec // G706
	}

	w.WriteHeader(http.StatusNoContent)
}
