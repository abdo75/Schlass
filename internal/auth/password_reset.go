// Package auth handles the self-service password reset flow:
// token mint, HMAC-peppered storage, single-use validation, and confirm.
// Every /request response is 200 with empty body (enumeration-safe).
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/abdo75/Schlass/internal/instanceconfig"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/abdo75/Schlass/internal/audit"
	"github.com/abdo75/Schlass/internal/crypto"
	"github.com/abdo75/Schlass/internal/httputil"
	"github.com/abdo75/Schlass/internal/mail"
	"github.com/abdo75/Schlass/internal/session"
	"github.com/abdo75/Schlass/internal/users"
	"github.com/abdo75/Schlass/internal/validate"
)

// PasswordResetHandler is enumeration-safe: every /request response is 200
// with empty body, and matched + unmatched paths both run a dummy Argon2id
// verify before branching so response timing doesn't distinguish them
// (mirrors login enumeration defense).
type PasswordResetHandler struct {
	pool              *pgxpool.Pool
	valkey            *redis.Client
	userStore         *users.Store
	tokenStore        *TokenStore
	auditStore        audit.Logger
	sessionStore      session.Store
	instanceConfig    *instanceconfig.Service
	publicURL         string
	dummyPasswordHash string
	hibpChecker       *crypto.HIBPChecker
}

func NewPasswordResetHandler(
	pool *pgxpool.Pool,
	valkey *redis.Client,
	userStore *users.Store,
	tokenStore *TokenStore,
	auditStore audit.Logger,
	sessionStore session.Store,
	instanceConfig *instanceconfig.Service,
	publicURL string,
	hibpChecker *crypto.HIBPChecker,
) (*PasswordResetHandler, error) {
	var pad [16]byte
	if _, err := rand.Read(pad[:]); err != nil {
		return nil, err
	}
	dummy, err := crypto.HashPassword("dummy-for-timing-" + base64.RawURLEncoding.EncodeToString(pad[:]))
	if err != nil {
		return nil, err
	}
	return &PasswordResetHandler{
		pool:              pool,
		valkey:            valkey,
		userStore:         userStore,
		tokenStore:        tokenStore,
		auditStore:        auditStore,
		sessionStore:      sessionStore,
		instanceConfig:    instanceConfig,
		publicURL:         publicURL,
		dummyPasswordHash: dummy,
		hibpChecker:       hibpChecker,
	}, nil
}

// PostRequest always returns 200 with empty body — enumeration guard.
// Disabled/non-active users fall through as unmatched.
func (h *PasswordResetHandler) PostRequest(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Even on decode error, return 200 — uniform outer shape prevents
		// distinguishing "bad JSON" from "unknown email".
		httputil.WriteJSON(w, http.StatusOK, map[string]any{})
		return
	}
	email := strings.TrimSpace(strings.ToLower(req.Email))
	if err := validate.Email(email); err != nil {
		httputil.WriteJSON(w, http.StatusOK, map[string]any{})
		return
	}

	// Dummy verify runs FIRST, before any branch that depends on match —
	// every response path pays the same Argon2id cost.
	_, _ = crypto.VerifyPassword("dummy-attempt", h.dummyPasswordHash)

	ipStr := extractClientIP(r)
	ipAddr := parseClientIPAddr(ipStr)

	u, err := h.userStore.GetByEmail(r.Context(), h.pool, email)
	if err != nil && !errors.Is(err, users.ErrUserNotFound) {
		// Pool error distinct from "no such user" — log it, still return 200
		// to preserve the enumeration-safety contract.
		slog.Error("password_reset.request: lookup", "error", err)
		httputil.WriteJSON(w, http.StatusOK, map[string]any{})
		return
	}
	// Disabled/non-active users take the unmatched path — login blocks them,
	// and a reset email would leak account-status signal.
	matched := err == nil && u != nil && u.Status == "active"

	// super_admin cannot self-reset via email (NIS2 phishing-resistant MFA
	// mandate; TOTP does not satisfy, so we block the flow entirely and
	// require operator CLI recovery). Route through the unmatched path so
	// the 200-with-empty-body contract + enumeration timing stay intact;
	// admin-specific audit row distinguishes forensically.
	if matched && u.Role == "super_admin" {
		matched = false
		bestEffortAudit(r.Context(), h.pool, h.auditStore, audit.Event{
			EventType:  "password_reset.admin_blocked",
			ActorID:    &u.ID,
			ActorEmail: u.Email,
			TargetType: "user",
			TargetID:   u.ID.String(),
			IPAddress:  ipStr,
			Outcome:    "success",
			Metadata:   map[string]any{"reason": "super_admin_cannot_self_reset"},
		})
	}

	if !matched {
		// Audit is the only signal that someone probed for this email. 200
		// contract is absolute; audit failure does not alter the response.
		bestEffortAudit(r.Context(), h.pool, h.auditStore, audit.Event{
			EventType:  "password_reset.requested",
			TargetType: "user",
			IPAddress:  ipStr,
			Outcome:    "success",
			Metadata: map[string]any{
				"email_matched":     false,
				"email_hash_prefix": sha256Prefix(email),
			},
		})
		httputil.WriteJSON(w, http.StatusOK, map[string]any{})
		return
	}

	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		slog.Error("password_reset.request: rand", "error", err)
		httputil.WriteJSON(w, http.StatusOK, map[string]any{})
		return
	}
	plaintextToken := base64.RawURLEncoding.EncodeToString(raw[:])

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("password_reset.request: begin tx", "error", err)
		httputil.WriteJSON(w, http.StatusOK, map[string]any{})
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	// OWASP-mandated: burn prior unused tokens so older emailed links fail
	// after a fresh /request.
	if _, err := h.tokenStore.InvalidateOutstandingForUser(r.Context(), tx, u.ID); err != nil {
		slog.Error("password_reset.request: invalidate prior", "error", err, "user_id", u.ID)
		httputil.WriteJSON(w, http.StatusOK, map[string]any{})
		return
	}

	tokenID, err := h.tokenStore.Insert(r.Context(), tx, u.ID, plaintextToken, 30*time.Minute, ipAddr)
	if err != nil {
		slog.Error("password_reset.request: insert token", "error", err, "user_id", u.ID)
		httputil.WriteJSON(w, http.StatusOK, map[string]any{})
		return
	}

	if err := h.auditStore.Emit(r.Context(), tx, audit.Event{
		EventType:  "password_reset.requested",
		ActorID:    &u.ID,
		ActorEmail: u.Email,
		TargetType: "user",
		TargetID:   u.ID.String(),
		IPAddress:  ipStr,
		Outcome:    "success",
		Metadata:   map[string]any{"email_matched": true, "token_id": tokenID.String()},
	}); err != nil {
		slog.Error("password_reset.request: audit", "error", err, "user_id", u.ID)
		httputil.WriteJSON(w, http.StatusOK, map[string]any{})
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("password_reset.request: commit", "error", err, "user_id", u.ID)
		httputil.WriteJSON(w, http.StatusOK, map[string]any{})
		return
	}

	// Fire-and-forget goroutine with background ctx: HTTP response must not
	// block on SMTP, and the send must survive client disconnect.
	//nolint:gosec // G118 — deliberate; request ctx would cancel the moment we return.
	go h.sendResetEmail(u.Email, plaintextToken)

	httputil.WriteJSON(w, http.StatusOK, map[string]any{})
}

// PostConfirm validates the token under SELECT FOR UPDATE (single-use +
// not-expired, atomic across concurrent confirms). Not-found / expired /
// already-used all collapse to INVALID_TOKEN so callers can't distinguish
// which failure mode fired. force_password_change=false: user actively
// chose this password via the reset link (matches self-change, not admin-
// reset which forces rotation).
func (h *PasswordResetHandler) PostConfirm(w http.ResponseWriter, r *http.Request) {
	ip := extractClientIP(r)

	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var req struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body.")
		return
	}
	if req.Token == "" {
		httputil.WriteError(w, http.StatusBadRequest, "INVALID_TOKEN", "Reset link is no longer valid.")
		return
	}

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("password_reset.confirm: begin tx", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	token, err := h.tokenStore.GetByTokenForUpdate(r.Context(), tx, req.Token)
	if err != nil {
		if errors.Is(err, ErrResetTokenNotFound) {
			h.auditConfirmFailed(r.Context(), "token_not_found", ip, nil)
			httputil.WriteError(w, http.StatusBadRequest, "INVALID_TOKEN", "Reset link is no longer valid.")
			return
		}
		slog.Error("password_reset.confirm: get token", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if token.UsedAt != nil || time.Now().After(token.ExpiresAt) {
		uid := token.UserID
		h.auditConfirmFailed(r.Context(), "token_invalid", ip, &uid)
		httputil.WriteError(w, http.StatusBadRequest, "INVALID_TOKEN", "Reset link is no longer valid.")
		return
	}

	policy, err := h.instanceConfig.PasswordPolicy(r.Context(), tx)
	if err != nil {
		slog.Error("password_reset.confirm: policy", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := validate.Password(req.Password, policy); err != nil {
		uid := token.UserID
		h.auditConfirmFailed(r.Context(), "policy_violation", ip, &uid)
		httputil.WriteError(w, http.StatusBadRequest, "PASSWORD_POLICY_VIOLATION", err.Error())
		return
	}

	// HIBP fail-open on network error — outages must not block password changes.
	if pwned, hibpErr := h.hibpChecker.IsPwned(r.Context(), req.Password); hibpErr != nil {
		slog.Warn("password_breach_check: hibp unavailable", "error", hibpErr)
	} else if pwned {
		httputil.WriteError(w, http.StatusBadRequest, "PASSWORD_BREACHED",
			"This password has appeared in a known data breach. Choose a different one.")
		return
	}

	hash, err := crypto.HashPassword(req.Password)
	if err != nil {
		slog.Error("password_reset.confirm: hash", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := h.userStore.SetPasswordHash(r.Context(), tx, token.UserID, hash, false); err != nil {
		slog.Error("password_reset.confirm: set password hash", "error", err, "user_id", token.UserID)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.userStore.ClearLockoutForPasswordChange(r.Context(), tx, token.UserID); err != nil {
		slog.Error("password_reset.confirm: clear lockout", "error", err, "user_id", token.UserID)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.tokenStore.MarkUsed(r.Context(), tx, token.ID); err != nil {
		slog.Error("password_reset.confirm: mark used", "error", err, "token_id", token.ID)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	userID := token.UserID
	if err := h.auditStore.Emit(r.Context(), tx, audit.Event{
		EventType:  "password_reset.completed",
		ActorID:    &userID,
		TargetType: "user",
		TargetID:   userID.String(),
		IPAddress:  ip,
		Outcome:    "success",
		Metadata:   map[string]any{"token_id": token.ID.String()},
	}); err != nil {
		slog.Error("password_reset.confirm: audit completed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.auditStore.Emit(r.Context(), tx, audit.Event{
		EventType:  "user.revoke_before_set",
		ActorID:    &userID,
		TargetType: "user",
		TargetID:   userID.String(),
		IPAddress:  ip,
		Outcome:    "success",
		Metadata:   map[string]any{"reason": "self_password_reset"},
	}); err != nil {
		slog.Error("password_reset.confirm: audit revoke_before_set", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("password_reset.confirm: commit", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	// Best-effort — committed DB state + audit row are the load-bearing events.
	if err := session.RevokeBeforeSetNow(r.Context(), h.valkey, userID.String()); err != nil {
		slog.Error("password_reset.confirm: revoke_before", "error", err, "user_id", userID)
	}
	if err := h.sessionStore.DeleteAllForUser(r.Context(), userID.String()); err != nil {
		slog.Error("password_reset.confirm: session wipe", "error", err, "user_id", userID)
	}

	// OWASP out-of-band notify. Goroutine captures the email string, not a
	// DB handle.
	if userEmail, err := h.userStore.GetEmail(r.Context(), h.pool, userID); err == nil && userEmail != "" {
		//nolint:gosec // G118 — fire-and-forget, see sendResetEmail.
		go h.sendPasswordChangedEmail(userEmail)
	} else if err != nil {
		slog.Error("password_reset.confirm: lookup email for notify", "error", err, "user_id", userID)
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{"user_id": userID.String()})
}

// PostValidate is read-only. Not-found / expired / used all collapse to
// INVALID_TOKEN. No rate limit — token is 32-byte crypto/rand, infeasible
// to brute-force within the 30-minute TTL.
func (h *PasswordResetHandler) PostValidate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body.")
		return
	}
	if req.Token == "" {
		httputil.WriteError(w, http.StatusBadRequest, "INVALID_TOKEN", "Reset link is no longer valid.")
		return
	}
	token, err := h.tokenStore.GetByToken(r.Context(), h.pool, req.Token)
	if err != nil {
		if errors.Is(err, ErrResetTokenNotFound) {
			httputil.WriteError(w, http.StatusBadRequest, "INVALID_TOKEN", "Reset link is no longer valid.")
			return
		}
		slog.Error("password_reset.validate: get token", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if token.UsedAt != nil || time.Now().After(token.ExpiresAt) {
		httputil.WriteError(w, http.StatusBadRequest, "INVALID_TOKEN", "Reset link is no longer valid.")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]any{})
}

// auditConfirmFailed writes its own short-lived tx (the confirm tx is
// about to roll back, so a tx-scoped audit would roll back too).
func (h *PasswordResetHandler) auditConfirmFailed(ctx context.Context, reason, ip string, userID *uuid.UUID) {
	event := audit.Event{
		EventType:  "password_reset.confirm_failed",
		TargetType: "user",
		IPAddress:  ip,
		Outcome:    "failure",
		Metadata:   map[string]any{"reason": reason},
	}
	if userID != nil {
		event.ActorID = userID
		event.TargetID = userID.String()
	}
	bestEffortAudit(ctx, h.pool, h.auditStore, event)
}

func (h *PasswordResetHandler) sendPasswordChangedEmail(to string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sender, err := mail.NewSenderFromConfig(ctx, h.instanceConfig, h.pool)
	if err != nil {
		slog.Error("password_reset.confirm: notify sender", "error", err, "to", to)
		return
	}
	instanceName, _ := h.instanceConfig.InstanceName(ctx, h.pool)
	if instanceName == "" {
		instanceName = "Schlass"
	}
	if err := sender.SendPasswordChanged(ctx, to, instanceName); err != nil {
		slog.Error("password_reset.confirm: notify send", "error", err, "to", to)
	}
}

func (h *PasswordResetHandler) sendResetEmail(to, token string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sender, err := mail.NewSenderFromConfig(ctx, h.instanceConfig, h.pool)
	if err != nil {
		slog.Error("password_reset.request: sender construct", "error", err, "to", to)
		return
	}
	instanceName, _ := h.instanceConfig.InstanceName(ctx, h.pool)
	if instanceName == "" {
		instanceName = "Schlass"
	}
	if err := sender.SendPasswordReset(ctx, to, token, instanceName, h.publicURL); err != nil {
		slog.Error("password_reset.request: send", "error", err, "to", to)
	}
}

// parseClientIPAddr: zero value on parse failure, which the store serializes
// as SQL NULL.
func parseClientIPAddr(s string) netip.Addr {
	if s == "" {
		return netip.Addr{}
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}
	}
	return addr
}

// sha256Prefix returns the first 8 hex chars of SHA-256(email) — a stable
// non-reversible correlation key for audit rows on unknown-email requests.
func sha256Prefix(email string) string {
	h := sha256.Sum256([]byte(email))
	return hex.EncodeToString(h[:4])
}
