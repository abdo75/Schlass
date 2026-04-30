package users

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/abdo75/Schlass/internal/instanceconfig"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/abdo75/Schlass/internal/audit"
	"github.com/abdo75/Schlass/internal/crypto"
	"github.com/abdo75/Schlass/internal/database"
	"github.com/abdo75/Schlass/internal/httputil"
	"github.com/abdo75/Schlass/internal/session"
)

// AuditLogger extends audit.Logger with the GDPR Art. 17 pseudonymize path.
// *audit.Store satisfies this; integration tests may inject a fake.
type AuditLogger interface {
	audit.Logger
	PseudonymizeUser(ctx context.Context, q database.Querier, userID uuid.UUID) (int, error)
}

type RecoveryCodeStore interface {
	DeleteAllForUser(ctx context.Context, q database.Querier, userID uuid.UUID) (int64, error)
}

// Handler handles all user management endpoints (CRUD, sessions, MFA reset).
type Handler struct {
	pool              *pgxpool.Pool
	valkey            *redis.Client
	userStore         *Store
	auditStore        AuditLogger
	sessionStore      session.Store
	instanceConfig    *instanceconfig.Service
	recoveryCodeStore RecoveryCodeStore
}

func NewHandler(
	pool *pgxpool.Pool,
	valkey *redis.Client,
	us *Store,
	as AuditLogger,
	sessionStore session.Store,
	instanceConfig *instanceconfig.Service,
	recoveryCodeStore RecoveryCodeStore,
) *Handler {
	return &Handler{
		pool:              pool,
		valkey:            valkey,
		userStore:         us,
		auditStore:        as,
		sessionStore:      sessionStore,
		instanceConfig:    instanceConfig,
		recoveryCodeStore: recoveryCodeStore,
	}
}

func pathParam(r *http.Request, name string) string {
	return r.PathValue(name)
}

func parseUserID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	raw := pathParam(r, "id")
	id, err := uuid.Parse(raw)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid user id.")
		return uuid.Nil, false
	}
	return id, true
}

// extractClientIP returns the leftmost IP from X-Forwarded-For when present,
// falling back to RemoteAddr. Shared by handlers that log client IPs for audit.
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

// rejectSelfOp short-circuits destructive ops targeting the caller's own
// account. Returns true when the caller must stop (401 unauth or 400
// CANNOT_OPERATE_ON_SELF). Also rejects when no user is in context so we
// never silently allow a self-op on a wiring bug.
func (h *Handler) rejectSelfOp(w http.ResponseWriter, r *http.Request, targetID uuid.UUID) bool {
	current, ok := CurrentUser(r.Context())
	if !ok {
		httputil.WriteError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return true
	}
	if current.ID == targetID {
		httputil.WriteError(w, http.StatusBadRequest, "CANNOT_OPERATE_ON_SELF", "You cannot perform this action on your own account.")
		return true
	}
	return false
}

// lockSuperAdminsForUpdate row-locks every super_admin so the caller can
// safely count remaining actives without a concurrent mutation changing the
// answer. Must be called inside a tx before remainingActiveSuperAdmins.
// Deliberately locks ALL super_admins (not just active ones) so the
// last-admin count check is also serialized against concurrent enable/disable
// flips.
func lockSuperAdminsForUpdate(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `SELECT id FROM users WHERE role = 'super_admin' FOR UPDATE`)
	return err
}

func remainingActiveSuperAdmins(ctx context.Context, tx pgx.Tx) (int, error) {
	var n int
	err := tx.QueryRow(ctx,
		`SELECT COUNT(*) FROM users
		 WHERE role = 'super_admin'
		   AND status = 'active'`,
	).Scan(&n)
	return n, err
}

// enforceLastAdminLockout is the compliance gate: rejects the request if
// the staged change would leave zero active super_admins. Must run inside
// the same tx that already applied the mutation.
func (h *Handler) enforceLastAdminLockout(ctx context.Context, tx pgx.Tx, w http.ResponseWriter) bool {
	n, err := remainingActiveSuperAdmins(ctx, tx)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return true
	}
	if n == 0 {
		httputil.WriteError(w, http.StatusBadRequest, "LAST_ADMIN_LOCKOUT", "Cannot leave the system without an active super_admin.")
		return true
	}
	return false
}

func uniqueViolationAsEmailConflict(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		httputil.WriteError(w, http.StatusConflict, "EMAIL_ALREADY_EXISTS", "A user with that email already exists.")
		return true
	}
	return false
}

type createUserRequest struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
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

	result, err := h.userStore.List(r.Context(), h.pool, ListUsersParams{
		Limit:       limit,
		Offset:      offset,
		EmailSearch: emailSearch,
	})
	if err != nil {
		slog.Error("users.List failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	usersOut := make([]map[string]any, 0, len(result.Users))
	for _, u := range result.Users {
		usersOut = append(usersOut, userDTO(u))
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"users":  usersOut,
		"total":  result.Total,
		"limit":  limit,
		"offset": offset,
	})
}

func userDTO(u *User) map[string]any {
	dto := map[string]any{
		"id":                    u.ID.String(),
		"email":                 u.Email,
		"role":                  u.Role,
		"status":                u.Status,
		"force_password_change": u.ForcePasswordChange,
		"created_at":            u.CreatedAt,
		"updated_at":            u.UpdatedAt,
		"totp_enrolled_at":      u.TOTPEnrolledAt,
		"last_login_at":         u.LastLoginAt,
	}
	return dto
}

func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body.")
		return
	}
	if req.Email == "" || !strings.Contains(req.Email, "@") {
		httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid email.")
		return
	}
	req.Email = strings.ToLower(req.Email)
	if req.Role != "super_admin" && req.Role != "user" {
		httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", "role must be 'super_admin' or 'user'.")
		return
	}

	tempPassword, err := crypto.GenerateTemporaryPassword()
	if err != nil {
		slog.Error("generate temporary password", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	hash, err := crypto.HashPassword(tempPassword)
	if err != nil {
		slog.Error("hash password", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	current, ok := CurrentUser(r.Context())
	if !ok {
		httputil.WriteError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}
	ip := extractClientIP(r)

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("begin tx", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	newID, err := h.userStore.Create(r.Context(), tx, req.Email, hash, req.Role, true)
	if err != nil {
		if uniqueViolationAsEmailConflict(w, err) {
			return
		}
		slog.Error("create user", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if auditErr := h.auditStore.Log(r.Context(), tx, audit.Entry{
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
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("commit create user", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	fresh, err := h.userStore.GetByID(r.Context(), h.pool, newID)
	if err != nil {
		slog.Error("fetch new user", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	httputil.WriteJSON(w, http.StatusCreated, map[string]any{
		"user":               userDTO(fresh),
		"temporary_password": tempPassword,
	})
}

func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUserID(w, r)
	if !ok {
		return
	}

	u, err := h.userStore.GetByID(r.Context(), h.pool, id)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			httputil.WriteError(w, http.StatusNotFound, "USER_NOT_FOUND", "User not found.")
			return
		}
		slog.Error("users.Get: fetch user", "error", err, "user_id", id) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	// Session store outage degrades gracefully — return the user DTO with
	// an empty sessions slice rather than failing the whole request.
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

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"user":     userDTO(u),
		"sessions": sessionsOut,
	})
}

type updateUserRequest struct {
	Email *string `json:"email,omitempty"`
	Role  *string `json:"role,omitempty"`
}

func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUserID(w, r)
	if !ok {
		return
	}

	var req updateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body.")
		return
	}
	if req.Email == nil && req.Role == nil {
		httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", "At least one of email or role is required.")
		return
	}
	if req.Email != nil {
		if *req.Email == "" || !strings.Contains(*req.Email, "@") {
			httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid email.")
			return
		}
		lower := strings.ToLower(*req.Email)
		req.Email = &lower
	}
	if req.Role != nil {
		if *req.Role != "super_admin" && *req.Role != "user" {
			httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", "role must be 'super_admin' or 'user'.")
			return
		}
	}

	// Self-email update is allowed; self-role change is not.
	if req.Role != nil && h.rejectSelfOp(w, r, id) {
		return
	}

	current, ok := CurrentUser(r.Context())
	if !ok {
		httputil.WriteError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}
	ip := extractClientIP(r)

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("users.Update: begin tx", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	existing, err := h.userStore.GetByID(r.Context(), tx, id)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			httputil.WriteError(w, http.StatusNotFound, "USER_NOT_FOUND", "User not found.")
			return
		}
		slog.Error("users.Update: fetch existing", "error", err, "user_id", id) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
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

	demoting := existing.Role == "super_admin" && newRole != "super_admin"
	if demoting {
		if err := lockSuperAdminsForUpdate(r.Context(), tx); err != nil {
			slog.Error("users.Update: lock super_admins", "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
	}

	if err := h.userStore.Update(r.Context(), tx, id, newEmail, newRole); err != nil {
		if uniqueViolationAsEmailConflict(w, err) {
			return
		}
		if errors.Is(err, ErrUserNotFound) {
			httputil.WriteError(w, http.StatusNotFound, "USER_NOT_FOUND", "User not found.")
			return
		}
		slog.Error("users.Update: update", "error", err, "user_id", id) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if demoting && h.enforceLastAdminLockout(r.Context(), tx, w) {
		return
	}

	type changedField struct {
		Field string `json:"field"`
		From  any    `json:"from"`
		To    any    `json:"to"`
	}
	var changed []changedField
	if req.Email != nil && *req.Email != existing.Email {
		changed = append(changed, changedField{Field: "email", From: existing.Email, To: *req.Email})
	}
	if req.Role != nil && *req.Role != existing.Role {
		changed = append(changed, changedField{Field: "role", From: existing.Role, To: *req.Role})
	}
	if len(changed) == 0 {
		if err := tx.Commit(r.Context()); err != nil {
			slog.Error("users.Update: no-op commit", "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
			return
		}
		httputil.WriteJSON(w, http.StatusOK, map[string]any{"user": userDTO(existing)})
		return
	}

	if auditErr := h.auditStore.Log(r.Context(), tx, audit.Entry{
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
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("users.Update: commit", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	fresh, err := h.userStore.GetByID(r.Context(), h.pool, id)
	if err != nil {
		slog.Error("users.Update: refetch", "error", err, "user_id", id) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]any{"user": userDTO(fresh)})
}

func (h *Handler) Disable(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUserID(w, r)
	if !ok {
		return
	}
	if h.rejectSelfOp(w, r, id) {
		return
	}

	current, ok := CurrentUser(r.Context())
	if !ok {
		httputil.WriteError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}
	ip := extractClientIP(r)

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("users.Disable: begin tx", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	// Lock the admin set up-front so the optional last-admin check below is
	// race-free. Cheap on ~1-10 rows and harmless for non-admin targets.
	if err := lockSuperAdminsForUpdate(r.Context(), tx); err != nil {
		slog.Error("users.Disable: lock super_admins", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	existing, err := h.userStore.GetByID(r.Context(), tx, id)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			httputil.WriteError(w, http.StatusNotFound, "USER_NOT_FOUND", "User not found.")
			return
		}
		slog.Error("users.Disable: fetch existing", "error", err, "user_id", id) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := h.userStore.SetStatus(r.Context(), tx, id, "disabled"); err != nil {
		if errors.Is(err, ErrUserNotFound) {
			httputil.WriteError(w, http.StatusNotFound, "USER_NOT_FOUND", "User not found.")
			return
		}
		slog.Error("users.Disable: set status", "error", err, "user_id", id) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if existing.Role == "super_admin" && h.enforceLastAdminLockout(r.Context(), tx, w) {
		return
	}

	if auditErr := h.auditStore.Log(r.Context(), tx, audit.Entry{
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
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if auditErr := h.auditStore.Log(r.Context(), tx, audit.Entry{
		EventType:  "user.revoke_before_set",
		ActorID:    &current.ID,
		ActorEmail: current.Email,
		TargetType: "user",
		TargetID:   id.String(),
		IPAddress:  ip,
		Outcome:    "success",
		Metadata:   map[string]any{"reason": "disable"},
	}); auditErr != nil {
		slog.Error("audit user.revoke_before_set (disable)", "error", auditErr)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("users.Disable: commit", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	// Post-commit, best-effort: DB is source of truth, the auth middleware's
	// disabled-user check rejects stale sessions on next request anyway.
	if err := h.sessionStore.DeleteAllForUser(r.Context(), id.String()); err != nil {
		slog.Warn("users.Disable: session revocation degraded", "error", err, "user_id", id) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
	}
	if err := session.RevokeBeforeSetNow(r.Context(), h.valkey, id.String()); err != nil {
		slog.Error("users.Disable: revoke_before Valkey write failed", "error", err, "user_id", id) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
	}

	w.WriteHeader(http.StatusNoContent)
}

// Enable has no self-op guard (enabling yourself is a no-op) and no
// last-admin lockout check (enabling can only grow the active admin count).
func (h *Handler) Enable(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUserID(w, r)
	if !ok {
		return
	}

	current, ok := CurrentUser(r.Context())
	if !ok {
		httputil.WriteError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}
	ip := extractClientIP(r)

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("users.Enable: begin tx", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	existing, err := h.userStore.GetByID(r.Context(), tx, id)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			httputil.WriteError(w, http.StatusNotFound, "USER_NOT_FOUND", "User not found.")
			return
		}
		slog.Error("users.Enable: fetch existing", "error", err, "user_id", id) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := h.userStore.SetStatus(r.Context(), tx, id, "active"); err != nil {
		if errors.Is(err, ErrUserNotFound) {
			httputil.WriteError(w, http.StatusNotFound, "USER_NOT_FOUND", "User not found.")
			return
		}
		slog.Error("users.Enable: set status", "error", err, "user_id", id) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if auditErr := h.auditStore.Log(r.Context(), tx, audit.Entry{
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
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("users.Enable: commit", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ResetPassword: server-generated temp password returned once; any body
// client sends is drained + discarded. force_password_change=true so the
// user must rotate on next login.
func (h *Handler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUserID(w, r)
	if !ok {
		return
	}

	if h.rejectSelfOp(w, r, id) {
		return
	}

	_, _ = io.Copy(io.Discard, r.Body)

	tempPassword, err := crypto.GenerateTemporaryPassword()
	if err != nil {
		slog.Error("users.ResetPassword: generate temp password", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	hash, err := crypto.HashPassword(tempPassword)
	if err != nil {
		slog.Error("users.ResetPassword: hash password", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	current, ok := CurrentUser(r.Context())
	if !ok {
		httputil.WriteError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}
	ip := extractClientIP(r)

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("users.ResetPassword: begin tx", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	existing, err := h.userStore.GetByID(r.Context(), tx, id)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			httputil.WriteError(w, http.StatusNotFound, "USER_NOT_FOUND", "User not found.")
			return
		}
		slog.Error("users.ResetPassword: fetch existing", "error", err, "user_id", id) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := h.userStore.SetPasswordHash(r.Context(), tx, id, hash, true); err != nil {
		if errors.Is(err, ErrUserNotFound) {
			httputil.WriteError(w, http.StatusNotFound, "USER_NOT_FOUND", "User not found.")
			return
		}
		slog.Error("users.ResetPassword: set password hash", "error", err, "user_id", id) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := h.userStore.ClearLockoutForPasswordChange(r.Context(), tx, id); err != nil {
		slog.Error("users.ResetPassword: clear lockout", "error", err, "user_id", id) //nolint:gosec // G706
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if auditErr := h.auditStore.Log(r.Context(), tx, audit.Entry{
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
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if auditErr := h.auditStore.Log(r.Context(), tx, audit.Entry{
		EventType:  "user.revoke_before_set",
		ActorID:    &current.ID,
		ActorEmail: current.Email,
		TargetType: "user",
		TargetID:   id.String(),
		IPAddress:  ip,
		Outcome:    "success",
		Metadata:   map[string]any{"reason": "password_reset"},
	}); auditErr != nil {
		slog.Error("audit user.revoke_before_set (password_reset)", "error", auditErr)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("users.ResetPassword: commit", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := h.sessionStore.DeleteAllForUser(r.Context(), id.String()); err != nil {
		slog.Warn("users.ResetPassword: session revocation degraded", "error", err, "user_id", id) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
	}
	if err := session.RevokeBeforeSetNow(r.Context(), h.valkey, id.String()); err != nil {
		slog.Error("users.ResetPassword: revoke_before Valkey write failed", "error", err, "user_id", id) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{"temporary_password": tempPassword})
}

// Delete hard-deletes the user row. audit_logs.actor_id FK was dropped in
// migration 000011 so the audit trail outlives the account. The victim row
// is captured BEFORE the delete so audit metadata carries the email + role.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUserID(w, r)
	if !ok {
		return
	}
	if h.rejectSelfOp(w, r, id) {
		return
	}

	current, ok := CurrentUser(r.Context())
	if !ok {
		httputil.WriteError(w, http.StatusUnauthorized, "INVALID_SESSION", "Not authenticated.")
		return
	}
	ip := extractClientIP(r)

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("users.Delete: begin tx", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	if err := lockSuperAdminsForUpdate(r.Context(), tx); err != nil {
		slog.Error("users.Delete: lock super_admins", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	target, err := h.userStore.GetByID(r.Context(), tx, id)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			httputil.WriteError(w, http.StatusNotFound, "USER_NOT_FOUND", "User not found.")
			return
		}
		slog.Error("users.Delete: fetch target", "error", err, "user_id", id) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := h.userStore.Delete(r.Context(), tx, id); err != nil {
		if errors.Is(err, ErrUserNotFound) {
			httputil.WriteError(w, http.StatusNotFound, "USER_NOT_FOUND", "User not found.")
			return
		}
		slog.Error("users.Delete: delete", "error", err, "user_id", id) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if target.Role == "super_admin" && h.enforceLastAdminLockout(r.Context(), tx, w) {
		return
	}

	// GDPR Art. 17 bridge: scrub actor_email on every audit row where the
	// deleted user was the actor. Runs inside the same tx as the user delete
	// so it's atomic with the erasure. The user.deleted row is still
	// attributable to the admin (actor_id != target id); ordering this BEFORE
	// the user.deleted Log() keeps that intent clear.
	rowsScrubbed, err := h.auditStore.PseudonymizeUser(r.Context(), tx, id)
	if err != nil {
		slog.Error("users.Delete: pseudonymize audit rows", "error", err, "user_id", id) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if auditErr := h.auditStore.Log(r.Context(), tx, audit.Entry{
		EventType:  "user.audit_pseudonymized",
		ActorID:    &current.ID,
		ActorEmail: current.Email,
		TargetType: "user",
		TargetID:   id.String(),
		IPAddress:  ip,
		Outcome:    "success",
		Metadata:   map[string]any{"rows_updated": rowsScrubbed},
	}); auditErr != nil {
		slog.Error("audit user.audit_pseudonymized", "error", auditErr, "user_id", id) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if auditErr := h.auditStore.Log(r.Context(), tx, audit.Entry{
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
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("users.Delete: commit", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := h.sessionStore.DeleteAllForUser(r.Context(), id.String()); err != nil {
		slog.Warn("users.Delete: session revocation degraded", "error", err, "user_id", id) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) ListSessions(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUserID(w, r)
	if !ok {
		return
	}

	sessions, err := h.sessionStore.ListByUser(r.Context(), id.String())
	if err != nil {
		slog.Error("users.ListSessions: session.ListByUser", "error", err, "user_id", id) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
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
	httputil.WriteJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

// TerminateAllSessions is a full identity revocation — bumps revoke_before
// so outstanding OIDC access + refresh tokens all fail on next use. Self-op
// is allowed (signing yourself out of all devices is a standard IDP feature).
func (h *Handler) TerminateAllSessions(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUserID(w, r)
	if !ok {
		return
	}

	current, _ := CurrentUser(r.Context())
	ip := extractClientIP(r)

	sessions, _ := h.sessionStore.ListByUser(r.Context(), id.String())
	beforeCount := len(sessions)

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("users.TerminateAllSessions: begin tx", "error", err) //nolint:gosec // G706
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	if err := h.auditStore.Log(r.Context(), tx, audit.Entry{
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
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := h.auditStore.Log(r.Context(), tx, audit.Entry{
		EventType:  "user.revoke_before_set",
		ActorID:    &current.ID,
		ActorEmail: current.Email,
		TargetType: "user",
		TargetID:   id.String(),
		IPAddress:  ip,
		Outcome:    "success",
		Metadata:   map[string]any{"reason": "sessions_terminated"},
	}); err != nil {
		slog.Error("users.TerminateAllSessions: audit user.revoke_before_set", "error", err) //nolint:gosec // G706
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("users.TerminateAllSessions: commit", "error", err) //nolint:gosec // G706
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := h.sessionStore.DeleteAllForUser(r.Context(), id.String()); err != nil {
		slog.Warn("users.TerminateAllSessions: session revocation degraded", "error", err, "user_id", id) //nolint:gosec // G706
	}

	if err := session.RevokeBeforeSetNow(r.Context(), h.valkey, id.String()); err != nil {
		slog.Error("users.TerminateAllSessions: revoke_before Valkey write failed", "error", err, "user_id", id) //nolint:gosec // G706
	}

	w.WriteHeader(http.StatusNoContent)
}

// ResetMFA — self-op rejected: an admin who lost their authenticator needs
// another super_admin to reset them (same philosophy as last-admin-lockout).
func (h *Handler) ResetMFA(w http.ResponseWriter, r *http.Request) {
	targetID, ok := parseUserID(w, r)
	if !ok {
		return
	}
	if h.rejectSelfOp(w, r, targetID) {
		return
	}

	acting, _ := CurrentUser(r.Context())

	target, err := h.userStore.GetByID(r.Context(), h.pool, targetID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			httputil.WriteError(w, http.StatusNotFound, "USER_NOT_FOUND", "User not found.")
			return
		}
		slog.Error("reset-mfa: GetByID failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if target.TOTPEnrolledAt == nil {
		httputil.WriteError(w, http.StatusBadRequest, "MFA_NOT_ENROLLED", "This user has not enrolled in MFA.")
		return
	}

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	deleted, err := h.recoveryCodeStore.DeleteAllForUser(r.Context(), tx, targetID)
	if err != nil {
		slog.Error("reset-mfa: DeleteAllForUser failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.userStore.ClearTOTP(r.Context(), tx, targetID); err != nil {
		slog.Error("reset-mfa: ClearTOTP failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	wasEnrolledAt := target.TOTPEnrolledAt.Format(time.RFC3339)
	if err := h.auditStore.Log(r.Context(), tx, audit.Entry{
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
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if auditErr := h.auditStore.Log(r.Context(), tx, audit.Entry{
		EventType:  "user.revoke_before_set",
		ActorID:    &acting.ID,
		ActorEmail: acting.Email,
		TargetType: "user",
		TargetID:   targetID.String(),
		IPAddress:  extractClientIP(r),
		Outcome:    "success",
		Metadata:   map[string]any{"reason": "mfa_reset"},
	}); auditErr != nil {
		slog.Error("audit user.revoke_before_set (mfa_reset)", "error", auditErr)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("reset-mfa: Commit failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := h.sessionStore.DeleteAllForUser(r.Context(), targetID.String()); err != nil {
		slog.Error("reset-mfa: DeleteAllForUser sessions failed", "error", err, "user_id", targetID.String()) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
	}
	if err := session.RevokeBeforeSetNow(r.Context(), h.valkey, targetID.String()); err != nil {
		slog.Error("reset-mfa: revoke_before Valkey write failed", "error", err, "user_id", targetID) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
	}

	updated, _ := h.userStore.GetByID(r.Context(), h.pool, targetID)
	httputil.WriteJSON(w, http.StatusOK, map[string]any{"user": userDTO(updated)})
}

// TerminateSession is per-device — self-op is allowed ("sign out my other
// laptop"). Does NOT bump revoke_before: an opaque admin-web session token
// cannot map to a specific OIDC token, and bumping the cutoff here would
// revoke every OIDC token regardless of device.
func (h *Handler) TerminateSession(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUserID(w, r)
	if !ok {
		return
	}
	token := pathParam(r, "token")
	if token == "" {
		httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Missing token.")
		return
	}

	current, _ := CurrentUser(r.Context())
	ip := extractClientIP(r)

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("users.TerminateSession: begin tx", "error", err) //nolint:gosec // G706
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	// Audit stores only the first 8 chars — full token is a secret and must
	// not appear outside the Valkey session key.
	tokenPrefix := token
	if len(tokenPrefix) > 8 {
		tokenPrefix = tokenPrefix[:8]
	}
	if err := h.auditStore.Log(r.Context(), tx, audit.Entry{
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
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("users.TerminateSession: commit", "error", err) //nolint:gosec // G706
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := h.sessionStore.Delete(r.Context(), id.String(), token); err != nil {
		slog.Warn("users.TerminateSession: session delete degraded", "error", err, "user_id", id) //nolint:gosec // G706
	}

	w.WriteHeader(http.StatusNoContent)
}
