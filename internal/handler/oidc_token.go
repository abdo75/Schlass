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
	refreshTokenTTL    = 24 * time.Hour // absolute TTL from initial code exchange (spec §5f)
	defaultTokenRateLimit = int64(60)   // per minute, per client_id (spec §5e)
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
		// M4 deliverable; a clean 400 lets RPs distinguish "wrong grant" from a server error.
		writeTokenError(w, http.StatusBadRequest, "unsupported_grant_type", "refresh_token grant lands in a subsequent milestone.")
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
