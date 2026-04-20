package handler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/abdo75/Schlass/internal/config"
	"github.com/abdo75/Schlass/internal/crypto"
	"github.com/abdo75/Schlass/internal/mail"
	"github.com/abdo75/Schlass/internal/model"
	"github.com/abdo75/Schlass/internal/revokebefore"
	"github.com/abdo75/Schlass/internal/session"
	"github.com/abdo75/Schlass/internal/store"
)

// PasswordResetHandler serves the public password-reset request endpoint.
// It is enumeration-safe by construction: every response path returns 200
// with an empty body regardless of whether the email matched a user, and
// the unknown-email path runs a dummy Argon2id verify so response timing
// does not distinguish the two states (mirrors the login enumeration
// defense described in CLAUDE.md).
type PasswordResetHandler struct {
	pool              *pgxpool.Pool
	valkey            *redis.Client
	userStore         *store.UserStore
	tokenStore        *store.PasswordResetTokenStore
	auditStore        AuditLogger
	sessionStore      session.Store
	configService     *config.ConfigService
	publicURL         string
	dummyPasswordHash string
}

func NewPasswordResetHandler(
	pool *pgxpool.Pool,
	valkey *redis.Client,
	userStore *store.UserStore,
	tokenStore *store.PasswordResetTokenStore,
	auditStore AuditLogger,
	sessionStore session.Store,
	configService *config.ConfigService,
	publicURL string,
) (*PasswordResetHandler, error) {
	// Pre-compute a dummy Argon2id hash so the unknown-email response
	// path's timing matches the real-user path (mirrors login enumeration
	// defense — see CLAUDE.md "Enumeration defense" paragraph).
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
		configService:     configService,
		publicURL:         publicURL,
		dummyPasswordHash: dummy,
	}, nil
}

// PostRequest serves POST /api/password-reset/request. Always returns
// 200 with empty body regardless of whether the email matches a user —
// this is the enumeration guard. If the email matches, mint a token +
// insert + audit + async email send. Otherwise run a constant-time
// Argon2id verify against the dummy hash so response timing does not
// distinguish the two paths.
func (h *PasswordResetHandler) PostRequest(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Even on decode error: return 200. Uniform outer shape so callers
		// cannot distinguish "bad JSON" from "unknown email".
		w.WriteHeader(http.StatusOK)
		return
	}
	email := strings.TrimSpace(strings.ToLower(req.Email))
	if err := model.ValidateEmail(email); err != nil {
		w.WriteHeader(http.StatusOK)
		return
	}

	ipStr := extractClientIP(r)
	ipAddr := parseClientIPAddr(ipStr)

	user, err := h.userStore.GetByEmail(r.Context(), h.pool, email)
	matched := err == nil && user != nil

	if !matched {
		// Constant-time dummy verify so hash cost appears in response timing.
		// Note: VerifyPassword(password, hash) — password first, hash second.
		_, _ = crypto.VerifyPassword("dummy-attempt", h.dummyPasswordHash)

		// Best-effort audit in a short-lived tx against the pool. Not
		// transactional with any state change because there is no state
		// change — the audit row is the only signal that someone probed
		// for this email. Failure logs ERROR but does not alter the
		// response; the 200 contract is absolute.
		if auditErr := h.auditStore.Log(r.Context(), h.pool, store.AuditEntry{
			EventType:  "password_reset.requested",
			TargetType: "user",
			IPAddress:  ipStr,
			Outcome:    "success",
			Metadata: map[string]any{
				"email_matched":     false,
				"email_hash_prefix": sha256Prefix(email),
			},
		}); auditErr != nil {
			slog.Error("password_reset.request: audit unmatched", "error", auditErr)
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	if err != nil && !errors.Is(err, store.ErrUserNotFound) {
		// Pool error on lookup — log and still return 200 (enumeration
		// guard). Request is lost; client can retry.
		slog.Error("password_reset.request: lookup", "error", err)
		w.WriteHeader(http.StatusOK)
		return
	}

	// Mint token — 32-byte crypto/rand, base64url-encoded.
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		slog.Error("password_reset.request: rand", "error", err)
		w.WriteHeader(http.StatusOK)
		return
	}
	plaintextToken := base64.RawURLEncoding.EncodeToString(raw[:])

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("password_reset.request: begin tx", "error", err)
		w.WriteHeader(http.StatusOK)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	tokenID, err := h.tokenStore.Insert(r.Context(), tx, user.ID, plaintextToken, 30*time.Minute, ipAddr)
	if err != nil {
		slog.Error("password_reset.request: insert token", "error", err, "user_id", user.ID)
		w.WriteHeader(http.StatusOK)
		return
	}

	if err := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
		EventType:  "password_reset.requested",
		ActorID:    &user.ID,
		ActorEmail: user.Email,
		TargetType: "user",
		TargetID:   user.ID.String(),
		IPAddress:  ipStr,
		Outcome:    "success",
		Metadata:   map[string]any{"email_matched": true, "token_id": tokenID.String()},
	}); err != nil {
		slog.Error("password_reset.request: audit", "error", err, "user_id", user.ID)
		w.WriteHeader(http.StatusOK)
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("password_reset.request: commit", "error", err, "user_id", user.ID)
		w.WriteHeader(http.StatusOK)
		return
	}

	// Async email send — goroutine with its own background ctx so the
	// HTTP response isn't blocked on SMTP, and so the send survives the
	// client closing the connection before SMTP finishes. Any failure
	// logs ERROR; no retry in v1 (user can re-request).
	//nolint:gosec // G118 — deliberate: see comment above (request ctx would be cancelled the moment we return 200).
	go h.sendResetEmail(user.Email, plaintextToken)

	w.WriteHeader(http.StatusOK)
}

// PostConfirm serves POST /api/password-reset/confirm. Validates the
// token under SELECT FOR UPDATE (single-use + not-expired guard, atomic
// across concurrent confirm attempts), validates the new password against
// the current instance_config policy, Argon2id-hashes, updates the user,
// marks the token used, and audits — all in one tx. Post-commit: bumps
// revoke_before and wipes Valkey sessions for the user, mirroring admin
// reset-password so every OIDC token and admin web session issued before
// the reset is rejected on next use.
//
// Not-found / expired / already-used all collapse to the same
// INVALID_TOKEN response so a caller cannot distinguish which failure
// mode fired — preserves the enumeration guard from the request endpoint.
func (h *PasswordResetHandler) PostConfirm(w http.ResponseWriter, r *http.Request) {
	ip := extractClientIP(r)

	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var req struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body.")
		return
	}
	if req.Token == "" {
		writeError(w, http.StatusBadRequest, "INVALID_TOKEN", "Reset link is no longer valid.")
		return
	}

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("password_reset.confirm: begin tx", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	token, err := h.tokenStore.GetByTokenForUpdate(r.Context(), tx, req.Token)
	if err != nil {
		if errors.Is(err, store.ErrResetTokenNotFound) {
			writeError(w, http.StatusBadRequest, "INVALID_TOKEN", "Reset link is no longer valid.")
			return
		}
		slog.Error("password_reset.confirm: get token", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if token.UsedAt != nil || time.Now().After(token.ExpiresAt) {
		writeError(w, http.StatusBadRequest, "INVALID_TOKEN", "Reset link is no longer valid.")
		return
	}

	policy, err := h.configService.GetPasswordPolicy(r.Context(), tx)
	if err != nil {
		slog.Error("password_reset.confirm: policy", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := model.ValidatePassword(req.Password, policy); err != nil {
		writeError(w, http.StatusBadRequest, "PASSWORD_POLICY_VIOLATION", err.Error())
		return
	}

	hash, err := crypto.HashPassword(req.Password)
	if err != nil {
		slog.Error("password_reset.confirm: hash", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	// force_password_change=false: the user actively chose this password
	// via the reset link; no reason to force another rotation on next
	// sign-in. Matches auth.PostChangePassword, not admin reset-password.
	if err := h.userStore.SetPasswordHash(r.Context(), tx, token.UserID, hash, false); err != nil {
		slog.Error("password_reset.confirm: set password hash", "error", err, "user_id", token.UserID)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	if err := h.tokenStore.MarkUsed(r.Context(), tx, token.ID); err != nil {
		slog.Error("password_reset.confirm: mark used", "error", err, "token_id", token.ID)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	userID := token.UserID
	if err := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
		EventType:  "password_reset.completed",
		ActorID:    &userID,
		TargetType: "user",
		TargetID:   userID.String(),
		IPAddress:  ip,
		Outcome:    "success",
		Metadata:   map[string]any{"token_id": token.ID.String()},
	}); err != nil {
		slog.Error("password_reset.confirm: audit", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("password_reset.confirm: commit", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	// Post-commit: revoke_before cutoff + wipe Valkey sessions. Mirrors
	// admin reset-password exactly — all OIDC tokens + admin web sessions
	// issued before this moment fail on next use. Best-effort: the
	// load-bearing compliance event is the committed DB state plus audit
	// row; Valkey failures log ERROR but do not affect the response.
	if err := revokebefore.SetNow(r.Context(), h.valkey, userID.String()); err != nil {
		slog.Error("password_reset.confirm: revoke_before", "error", err, "user_id", userID)
	}
	if err := h.sessionStore.DeleteAllForUser(r.Context(), userID.String()); err != nil {
		slog.Error("password_reset.confirm: session wipe", "error", err, "user_id", userID)
	}

	writeJSON(w, http.StatusOK, map[string]any{"user_id": userID.String()})
}

// sendResetEmail runs in a goroutine post-commit. Loads SMTP config +
// instance name + dispatches via internal/mail. Fire-and-forget.
func (h *PasswordResetHandler) sendResetEmail(to, token string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sender, err := mail.NewSenderFromConfig(ctx, h.configService, h.pool)
	if err != nil {
		slog.Error("password_reset.request: sender construct", "error", err, "to", to)
		return
	}
	instanceName, _ := h.configService.GetInstanceName(ctx, h.pool)
	if instanceName == "" {
		instanceName = "Schlass"
	}
	if err := sender.SendPasswordReset(ctx, to, token, instanceName, h.publicURL); err != nil {
		slog.Error("password_reset.request: send", "error", err, "to", to)
	}
}

// parseClientIPAddr turns the string IP from extractClientIP into a
// netip.Addr for the store's INET column. Returns the zero value on
// parse failure, which the store serializes as SQL NULL.
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

// sha256Prefix returns the first 8 hex chars of SHA-256(email) — a
// stable non-reversible correlation key for audit rows on
// unknown-email requests. Leaks no PII (can't be brute-forced on a
// general email-space within the audit retention window).
func sha256Prefix(email string) string {
	h := sha256.Sum256([]byte(email))
	return hex.EncodeToString(h[:4])
}
