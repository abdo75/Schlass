package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/abdo75/Schlass/internal/oidc"
	"github.com/abdo75/Schlass/internal/revokebefore"
	"github.com/abdo75/Schlass/internal/session"
	"github.com/abdo75/Schlass/internal/store"
)

// tokenResponse is the RFC 6749 §5.1 success response body.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"` // always "Bearer"
	ExpiresIn    int    `json:"expires_in"` // seconds
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

const (
	refreshTokenTTL       = 24 * time.Hour // absolute TTL from initial code exchange (spec §5f)
	defaultTokenRateLimit = int64(60)      // per minute, per client_id (spec §5e)
)

// OIDCTokenHandler serves POST /token for the authorization_code grant.
// Refresh-token grant lands in M4 as an additive dispatch branch.
type OIDCTokenHandler struct {
	pool            *pgxpool.Pool
	valkey          *redis.Client
	clientStore     *store.ClientStore
	codeStore       *store.AuthCodeStore
	signingKeyStore *store.SigningKeyStore
	userStore       *store.UserStore
	auditStore      AuditLogger
	sessionStore    session.Store
	refreshStore    oidc.RefreshStore
	publicURL       string
	encryptionKey   []byte
	tokenRateLimit  int64
}

func NewOIDCTokenHandler(
	pool *pgxpool.Pool,
	valkey *redis.Client,
	userStore *store.UserStore,
	auditStore AuditLogger,
	sessionStore session.Store,
	publicURL string,
	encryptionKey []byte,
	tokenRateLimit int64,
) *OIDCTokenHandler {
	limit := defaultTokenRateLimit
	if tokenRateLimit > 0 {
		limit = tokenRateLimit
	}
	return &OIDCTokenHandler{
		pool:            pool,
		valkey:          valkey,
		clientStore:     store.NewClientStore(),
		codeStore:       store.NewAuthCodeStore(),
		signingKeyStore: store.NewSigningKeyStore(),
		userStore:       userStore,
		auditStore:      auditStore,
		sessionStore:    sessionStore,
		refreshStore:    oidc.NewRefreshStore(valkey),
		publicURL:       publicURL,
		encryptionKey:   encryptionKey,
		tokenRateLimit:  limit,
	}
}

// Handle routes POST /token. Dispatches on grant_type; only authorization_code
// is implemented in M3. refresh_token returns 400 unsupported_grant_type until M4.
func (h *OIDCTokenHandler) Handle(w http.ResponseWriter, r *http.Request) {
	// Always no-store on token responses (RFC 6749 §5.1).
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	// Bound the form body size before parsing to prevent memory exhaustion.
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "Malformed form body.")
		return
	}

	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		h.handleAuthorizationCode(w, r)
	case "refresh_token":
		h.handleRefreshToken(w, r)
	default:
		writeTokenError(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type not supported.")
	}
}

func (h *OIDCTokenHandler) handleAuthorizationCode(w http.ResponseWriter, r *http.Request) {
	// 1. Extract + basic validation of form params.
	clientID := r.PostForm.Get("client_id")
	clientSecret := r.PostForm.Get("client_secret")
	code := r.PostForm.Get("code")
	redirectURI := r.PostForm.Get("redirect_uri")
	codeVerifier := r.PostForm.Get("code_verifier")

	if clientID == "" || clientSecret == "" {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Missing client credentials.")
		return
	}
	if code == "" || redirectURI == "" || codeVerifier == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "Missing code, redirect_uri, or code_verifier.")
		return
	}

	// 2. Rate-limit per client_id (spec §5e). Keyed in Valkey after body parse.
	if allowed, err := h.rateLimitCheck(r.Context(), clientID); err != nil {
		slog.Warn("token: rate limit check failed (allowing)", "error", err)
	} else if !allowed {
		writeTokenError(w, http.StatusTooManyRequests, "invalid_request", "Rate limit exceeded for this client.")
		return
	}

	// 3. Client authentication. Failure → 401 invalid_client + best-effort audit.
	ok, err := h.clientStore.VerifySecret(r.Context(), h.pool, clientID, clientSecret)
	if err != nil || !ok {
		h.writeBestEffortAudit(r, store.AuditEntry{
			EventType:  "oidc.client.auth_failed",
			TargetType: "client",
			TargetID:   clientID,
			IPAddress:  extractClientIP(r),
			Outcome:    "failure",
			Metadata:   map[string]any{"reason": "secret_verify_failed"},
		})
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Client authentication failed.")
		return
	}
	client, err := h.clientStore.GetByID(r.Context(), h.pool, clientID)
	if err != nil {
		// Shouldn't happen — VerifySecret just succeeded. Defensive path.
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Client not found.")
		return
	}

	// 4. Consume the authorization code atomically.
	codeHash := sha256hex([]byte(code))
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Could not begin transaction.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	row, consumeErr := h.codeStore.ConsumeOnce(r.Context(), tx, codeHash)
	if errors.Is(consumeErr, store.ErrAuthCodeAlreadyUsed) {
		// Roll back BEFORE taking the replay path — replay opens its own tx.
		_ = tx.Rollback(r.Context())
		h.handleCodeReplay(r, w, codeHash)
		return
	}
	if consumeErr != nil {
		slog.Error("token: consume code", "error", consumeErr)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Could not consume authorization code.")
		return
	}

	// 5. Verify code ↔ client binding.
	if row.ClientID != client.ID {
		// Theft indicator: code was issued for a different client. Burn via ConsumeOnce, reject.
		_ = tx.Commit(r.Context())
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Code / client mismatch.")
		return
	}

	// 6. Verify redirect_uri matches the one stored on the code.
	if row.RedirectURI != redirectURI {
		_ = tx.Commit(r.Context())
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch.")
		return
	}

	// 7. Verify PKCE.
	if !oidc.VerifyPKCE(row.CodeChallenge, codeVerifier) {
		_ = tx.Commit(r.Context())
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "PKCE verifier mismatch.")
		return
	}

	// 8. Re-fetch user + status check.
	user, err := h.userStore.GetByID(r.Context(), tx, row.UserID)
	if err != nil {
		_ = tx.Commit(r.Context())
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "User not found.")
		return
	}
	if user.Status != "active" {
		// Audit user_disabled inside the same tx as the burned code.
		if auditErr := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
			EventType:  "oidc.code.user_disabled",
			ActorID:    &user.ID,
			ActorEmail: user.Email,
			TargetType: "client",
			TargetID:   client.ID.String(),
			ClientID:   &client.ID,
			IPAddress:  extractClientIP(r),
			Outcome:    "failure",
			Metadata:   map[string]any{"family_id": row.FamilyID.String()},
		}); auditErr != nil {
			slog.Error("token: user_disabled audit", "error", auditErr)
		}
		if err := tx.Commit(r.Context()); err != nil {
			writeTokenError(w, http.StatusInternalServerError, "server_error", "Could not commit.")
			return
		}
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "User not active.")
		return
	}

	// 9. Load active signing key + decrypt private key.
	activeKey, err := h.signingKeyStore.GetActive(r.Context(), tx)
	if err != nil {
		slog.Error("token: GetActive signing key", "error", err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "No active signing key.")
		return
	}
	privPEM, err := oidc.UnwrapPrivateKey(activeKey.PrivateKeyEncrypted, h.encryptionKey)
	if err != nil {
		slog.Error("token: unwrap private key", "error", err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Signing failed.")
		return
	}

	// 10. Build + sign access and ID tokens.
	now := time.Now().UTC()
	scopes := oidc.Scopes(row.Scopes)
	jtiAccess := uuid.NewString()
	accessClaims := oidc.BuildAccessClaims(user, client.ID.String(), h.publicURL, jtiAccess, scopes, now)
	accessTok, err := oidc.SignAccessToken(accessClaims, activeKey.ID.String(), privPEM)
	if err != nil {
		slog.Error("token: sign access token", "error", err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Signing failed.")
		return
	}

	// auth_time approximation: the code's ExpiresAt is "created_at + 60s", so
	// ExpiresAt - 60s ≈ the moment the user authenticated and the code was
	// minted at /authorize. Good enough for v1; a precise value would require
	// reading the session at /authorize time and plumbing it through.
	authTime := row.ExpiresAt.Add(-authCodeTTL)
	nonce := ""
	if row.Nonce != nil {
		nonce = *row.Nonce
	}
	jtiID := uuid.NewString()
	idClaims := oidc.BuildIDClaims(user, client.ID.String(), h.publicURL, jtiID, nonce, scopes, authTime, now)
	idTok, err := oidc.SignIDToken(idClaims, activeKey.ID.String(), privPEM)
	if err != nil {
		slog.Error("token: sign id token", "error", err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Signing failed.")
		return
	}

	// 11. Mint refresh token iff offline_access in scopes.
	var refreshTokenStr string
	if scopes.Has("offline_access") {
		tok, err := h.refreshStore.Create(r.Context(), oidc.RefreshPayload{
			UserID:    user.ID.String(),
			ClientID:  client.ID.String(),
			Scopes:    row.Scopes,
			FamilyID:  row.FamilyID.String(),
			CreatedAt: now.Unix(),
			Expires:   now.Add(refreshTokenTTL).Unix(),
		})
		if err != nil {
			slog.Error("token: refresh create", "error", err)
			writeTokenError(w, http.StatusInternalServerError, "server_error", "Could not mint refresh token.")
			return
		}
		refreshTokenStr = tok
	}

	// 12. Audit oidc.code.exchanged in the same tx as the code consume.
	if err := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
		EventType:  "oidc.code.exchanged",
		ActorID:    &user.ID,
		ActorEmail: user.Email,
		TargetType: "client",
		TargetID:   client.ID.String(),
		ClientID:   &client.ID,
		IPAddress:  extractClientIP(r),
		Outcome:    "success",
		Metadata: map[string]any{
			"family_id":      row.FamilyID.String(),
			"scopes":         row.Scopes,
			"access_jti":     jtiAccess,
			"id_jti":         jtiID,
			"refresh_issued": refreshTokenStr != "",
		},
	}); err != nil {
		slog.Error("token: audit oidc.code.exchanged", "error", err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Audit failed.")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("token: commit", "error", err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Commit failed.")
		return
	}

	// 13. Respond.
	resp := tokenResponse{
		AccessToken:  accessTok,
		TokenType:    "Bearer",
		ExpiresIn:    int(oidc.AccessTokenTTL.Seconds()),
		RefreshToken: refreshTokenStr,
		IDToken:      idTok,
		Scope:        scopes.String(),
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleCodeReplay revokes the refresh-token family tied to the already-used
// code and audits oidc.code.replay_detected. Per OAuth 2.1 §4.1.3.
func (h *OIDCTokenHandler) handleCodeReplay(r *http.Request, w http.ResponseWriter, codeHash string) {
	familyID, err := h.codeStore.LookupFamilyByCodeHash(r.Context(), h.pool, codeHash)
	if err != nil {
		// Can't look up family — code hash unknown entirely. Still return invalid_grant.
		slog.Error("token: LookupFamilyByCodeHash on replay", "error", err)
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Code already used.")
		return
	}
	if err := h.refreshStore.RevokeFamily(r.Context(), familyID.String()); err != nil {
		slog.Error("token: RevokeFamily on replay", "error", err)
		// Continue — we still want the audit row even if Valkey revoke failed.
	}

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("token: replay audit begin", "error", err)
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Code already used.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	if err := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
		EventType:  "oidc.code.replay_detected",
		TargetType: "authorization_code",
		IPAddress:  extractClientIP(r),
		Outcome:    "failure",
		Metadata:   map[string]any{"family_id": familyID.String()},
	}); err != nil {
		slog.Error("token: replay audit log", "error", err)
	}
	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("token: replay audit commit", "error", err)
	}
	writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Code already used.")
}

// rateLimitCheck increments ratelimit:oidc:token:<client_id> in a fixed
// 60-second window. Returns (true, nil) to proceed, (false, nil) if over cap.
func (h *OIDCTokenHandler) rateLimitCheck(ctx context.Context, clientID string) (bool, error) {
	key := "ratelimit:oidc:token:" + clientID
	count, err := h.valkey.Incr(ctx, key).Result()
	if err != nil {
		return true, err
	}
	if count == 1 {
		// First request in this window — set TTL.
		_ = h.valkey.Expire(ctx, key, time.Minute).Err()
	}
	return count <= h.tokenRateLimit, nil
}

// writeBestEffortAudit persists an audit row in its own tx. Failure is logged
// but does not block the caller. Matches the pattern used by /authorize.
func (h *OIDCTokenHandler) writeBestEffortAudit(r *http.Request, entry store.AuditEntry) {
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("token best-effort audit: begin", "error", err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	if err := h.auditStore.Log(r.Context(), tx, entry); err != nil {
		slog.Error("token best-effort audit: log", "error", err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("token best-effort audit: commit", "error", err)
	}
}

// handleRefreshToken implements the refresh_token grant per OAuth 2.1 §6 +
// spec §6c. Every successful rotation uses the same family_id and preserves
// the absolute expiry from the original code exchange (spec §5f).
func (h *OIDCTokenHandler) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	clientID := r.PostForm.Get("client_id")
	clientSecret := r.PostForm.Get("client_secret")
	presentedRefresh := r.PostForm.Get("refresh_token")

	if clientID == "" || clientSecret == "" {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Missing client credentials.")
		return
	}
	if presentedRefresh == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "Missing refresh_token.")
		return
	}

	// 1. Rate-limit per client_id (same bucket as auth_code grant, spec §5e).
	if allowed, err := h.rateLimitCheck(r.Context(), clientID); err != nil {
		slog.Warn("token refresh: rate limit check failed (allowing)", "error", err)
	} else if !allowed {
		writeTokenError(w, http.StatusTooManyRequests, "invalid_request", "Rate limit exceeded for this client.")
		return
	}

	// 2. Client authentication.
	ok, err := h.clientStore.VerifySecret(r.Context(), h.pool, clientID, clientSecret)
	if err != nil || !ok {
		h.writeBestEffortAudit(r, store.AuditEntry{
			EventType:  "oidc.client.auth_failed",
			TargetType: "client",
			TargetID:   clientID,
			IPAddress:  extractClientIP(r),
			Outcome:    "failure",
			Metadata:   map[string]any{"reason": "secret_verify_failed", "grant": "refresh_token"},
		})
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Client authentication failed.")
		return
	}
	client, err := h.clientStore.GetByID(r.Context(), h.pool, clientID)
	if err != nil {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Client not found.")
		return
	}

	// 3. Consume presented refresh token. Dispatch on sentinel errors.
	oldPayload, consumeErr := h.refreshStore.Consume(r.Context(), presentedRefresh)
	if errors.Is(consumeErr, oidc.ErrRefreshUnknownOrExpired) {
		// No family to revoke — we can't even identify the token.
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Refresh token invalid or expired.")
		return
	}
	if errors.Is(consumeErr, oidc.ErrRefreshReuseDetected) {
		// OAuth 2.1 §4.13: presented token was already rotated — revoke the
		// entire family and audit the event (best-effort tx is acceptable; the
		// Valkey revoke is the authoritative guard, not the audit row).
		if oldPayload != nil {
			if err := h.refreshStore.RevokeFamily(r.Context(), oldPayload.FamilyID); err != nil {
				slog.Error("token refresh: RevokeFamily on reuse", "error", err)
			}
			h.writeBestEffortAudit(r, store.AuditEntry{
				EventType:  "oidc.refresh.reuse_detected",
				ActorID:    uuidPtr(oldPayload.UserID),
				TargetType: "client",
				TargetID:   client.ID.String(),
				ClientID:   &client.ID,
				IPAddress:  extractClientIP(r),
				Outcome:    "failure",
				Metadata:   map[string]any{"family_id": oldPayload.FamilyID},
			})
		}
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Refresh token already used (family revoked).")
		return
	}
	if consumeErr != nil {
		slog.Error("token refresh: Consume", "error", consumeErr)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Refresh lookup failed.")
		return
	}

	// 4. Verify client binding — the refresh payload must belong to the caller.
	if oldPayload.ClientID != client.ID.String() {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Refresh / client mismatch.")
		return
	}

	// 5. Re-fetch user + status check.
	userUUID, err := uuid.Parse(oldPayload.UserID)
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Refresh payload malformed.")
		return
	}
	user, err := h.userStore.GetByID(r.Context(), h.pool, userUUID)
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "User not found.")
		return
	}
	if user.Status != "active" {
		if err := h.refreshStore.RevokeFamily(r.Context(), oldPayload.FamilyID); err != nil {
			slog.Error("token refresh: RevokeFamily on disabled-user", "error", err)
		}
		h.writeBestEffortAudit(r, store.AuditEntry{
			EventType:  "oidc.refresh.user_disabled",
			ActorID:    &user.ID,
			ActorEmail: user.Email,
			TargetType: "client",
			TargetID:   client.ID.String(),
			ClientID:   &client.ID,
			IPAddress:  extractClientIP(r),
			Outcome:    "failure",
			Metadata:   map[string]any{"family_id": oldPayload.FamilyID},
		})
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "User not active.")
		return
	}

	// 6-pre. revoke_before: reject if the refresh was issued before the user
	// mutation cutoff (spec §5g). We anchor on the refresh's CreatedAt (not
	// the access token's iat) because the refresh is what we're rotating; any
	// access token derived from it inherits the same stale provenance. Fail-open
	// on transport errors — a Valkey blip must not revoke all active sessions.
	rbCutoff, rbErr := revokebefore.Get(r.Context(), h.valkey, user.ID.String())
	if rbErr == nil && oldPayload.CreatedAt < rbCutoff.Unix() {
		if rerr := h.refreshStore.RevokeFamily(r.Context(), oldPayload.FamilyID); rerr != nil {
			slog.Error("token refresh: RevokeFamily on revoke_before", "error", rerr)
		}
		h.writeBestEffortAudit(r, store.AuditEntry{
			EventType:  "user.revoke_before_enforced",
			ActorID:    &user.ID,
			ActorEmail: user.Email,
			TargetType: "client",
			TargetID:   client.ID.String(),
			ClientID:   &client.ID,
			IPAddress:  extractClientIP(r),
			Outcome:    "failure",
			Metadata: map[string]any{
				"family_id":          oldPayload.FamilyID,
				"refresh_created_at": oldPayload.CreatedAt,
				"revoke_before":      rbCutoff.Unix(),
			},
		})
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Token revoked by user mutation.")
		return
	}
	if rbErr != nil && rbErr != revokebefore.ErrNotSet {
		slog.Warn("token refresh: revoke_before Get failed (allowing)", "error", rbErr)
	}

	// 6. Load active signing key.
	activeKey, err := h.signingKeyStore.GetActive(r.Context(), h.pool)
	if err != nil {
		slog.Error("token refresh: GetActive", "error", err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "No active signing key.")
		return
	}
	privPEM, err := oidc.UnwrapPrivateKey(activeKey.PrivateKeyEncrypted, h.encryptionKey)
	if err != nil {
		slog.Error("token refresh: unwrap private key", "error", err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Signing failed.")
		return
	}

	// 7. Sign new access + id tokens.
	now := time.Now().UTC()
	scopes := oidc.Scopes(oldPayload.Scopes)
	jtiAccess := uuid.NewString()
	jtiID := uuid.NewString()
	accessClaims := oidc.BuildAccessClaims(user, client.ID.String(), h.publicURL, jtiAccess, scopes, now)
	accessTok, err := oidc.SignAccessToken(accessClaims, activeKey.ID.String(), privPEM)
	if err != nil {
		slog.Error("token refresh: sign access", "error", err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Signing failed.")
		return
	}
	// auth_time is not re-derivable at refresh time; use the refresh's CreatedAt
	// as a floor (it was set at code-exchange time).
	authTime := time.Unix(oldPayload.CreatedAt, 0).UTC()
	idClaims := oidc.BuildIDClaims(user, client.ID.String(), h.publicURL, jtiID, "", scopes, authTime, now)
	idTok, err := oidc.SignIDToken(idClaims, activeKey.ID.String(), privPEM)
	if err != nil {
		slog.Error("token refresh: sign id", "error", err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Signing failed.")
		return
	}

	// 8. Mint rotated refresh. Same family_id; absolute expiry preserved from
	//    original code exchange (spec §5f — Create takes an absolute unix timestamp
	//    and computes TTL = exp - now, so passing oldPayload.Expires enforces the
	//    24h ceiling without resetting it on each rotation).
	newRefresh, err := h.refreshStore.Create(r.Context(), oidc.RefreshPayload{
		UserID:    user.ID.String(),
		ClientID:  client.ID.String(),
		Scopes:    oldPayload.Scopes,
		FamilyID:  oldPayload.FamilyID,
		CreatedAt: now.Unix(),
		Expires:   oldPayload.Expires, // absolute, not now+24h
	})
	if err != nil {
		// Create returns an error when exp is already in the past. The old token
		// is still consumable (used=false hasn't been flipped) so the RP gets a
		// clear "expired" signal rather than losing their session silently.
		slog.Warn("token refresh: Create rotated refresh failed", "error", err)
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Refresh token expired.")
		return
	}

	// 9. MarkUsed the old token. Ordering rationale: Create runs first so the RP
	//    always gets usable tokens even if MarkUsed fails (RP can still use the new
	//    refresh). If MarkUsed fails and the RP re-presents the old token, Consume
	//    returns used=false again — a duplicate rotation window exists, but the
	//    family_id linkage means a future reuse attack on *either* copy still
	//    triggers RevokeFamily. This is preferable to denying the user their tokens
	//    by aborting the response on a MarkUsed failure.
	if err := h.refreshStore.MarkUsed(r.Context(), presentedRefresh); err != nil {
		slog.Error("token refresh: MarkUsed old token", "error", err, "family_id", oldPayload.FamilyID) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
		// Continue — new tokens are already minted; MarkUsed failure is logged,
		// not returned.
	}

	// 10. Audit oidc.token.refreshed inside a tx (state-change audit rule).
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("token refresh: audit begin", "error", err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "DB begin failed.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	if err := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
		EventType:  "oidc.token.refreshed",
		ActorID:    &user.ID,
		ActorEmail: user.Email,
		TargetType: "client",
		TargetID:   client.ID.String(),
		ClientID:   &client.ID,
		IPAddress:  extractClientIP(r),
		Outcome:    "success",
		Metadata: map[string]any{
			"family_id":      oldPayload.FamilyID,
			"scopes":         oldPayload.Scopes,
			"new_access_jti": jtiAccess,
			"new_id_jti":     jtiID,
		},
	}); err != nil {
		slog.Error("token refresh: audit log", "error", err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Audit failed.")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("token refresh: audit commit", "error", err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Commit failed.")
		return
	}

	// 11. Respond with rotated tokens.
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  accessTok,
		TokenType:    "Bearer",
		ExpiresIn:    int(oidc.AccessTokenTTL.Seconds()),
		RefreshToken: newRefresh,
		IDToken:      idTok,
		Scope:        scopes.String(),
	})
}

// uuidPtr parses s into a *uuid.UUID, returning nil on parse failure.
// Used to populate optional ActorID fields from string payloads.
func uuidPtr(s string) *uuid.UUID {
	u, err := uuid.Parse(s)
	if err != nil {
		return nil
	}
	return &u
}

// writeTokenError writes an RFC 6749 §5.2 error response. The caller must
// have already set Cache-Control: no-store (Handle does this at entry).
func writeTokenError(w http.ResponseWriter, status int, oauthErr, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             oauthErr,
		"error_description": description,
	})
}
