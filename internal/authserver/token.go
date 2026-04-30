package authserver

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

	"github.com/abdo75/Schlass/internal/audit"
	"github.com/abdo75/Schlass/internal/clients"
	"github.com/abdo75/Schlass/internal/database"
	"github.com/abdo75/Schlass/internal/httputil"
	"github.com/abdo75/Schlass/internal/instanceconfig"
	"github.com/abdo75/Schlass/internal/oidc"
	"github.com/abdo75/Schlass/internal/session"
	authsigningkeys "github.com/abdo75/Schlass/internal/signingkeys"
	"github.com/abdo75/Schlass/internal/users"
)

// intersectScopesAgainstClient preserves the order of `granted`. An admin
// PATCH may narrow `allowed` between issuance and use — refresh + auth_code
// grants both re-validate here.
func intersectScopesAgainstClient(granted, allowed []string) ([]string, error) {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, s := range allowed {
		allowedSet[s] = struct{}{}
	}
	out := make([]string, 0, len(granted))
	for _, s := range granted {
		if _, ok := allowedSet[s]; ok {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("invalid_scope")
	}
	return out, nil
}

// tokenResponse — RFC 6749 §5.1 success body.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// TokenHandler serves POST /token (authorization_code + refresh_token grants).
type TokenHandler struct {
	pool            *pgxpool.Pool
	valkey          *redis.Client
	clientStore     *clients.Store
	codeStore       *AuthCodeStore
	signingKeyStore *authsigningkeys.Store
	userStore       *users.Store
	auditStore      audit.Logger
	sessionStore    session.Store
	instanceConfig  *instanceconfig.Service
	refreshStore    oidc.RefreshStore
	publicURL       string
	encryptionKey   []byte
	tokenRateLimit  int64
}

func NewTokenHandler(
	pool *pgxpool.Pool,
	valkey *redis.Client,
	userStore *users.Store,
	auditStore audit.Logger,
	sessionStore session.Store,
	instanceConfig *instanceconfig.Service,
	publicURL string,
	encryptionKey []byte,
	tokenRateLimit int64,
) *TokenHandler {
	return &TokenHandler{
		pool:            pool,
		valkey:          valkey,
		clientStore:     clients.NewStore(),
		codeStore:       NewAuthCodeStore(),
		signingKeyStore: authsigningkeys.NewStore(),
		userStore:       userStore,
		auditStore:      auditStore,
		sessionStore:    sessionStore,
		instanceConfig:  instanceConfig,
		refreshStore:    oidc.NewRefreshStore(valkey),
		publicURL:       publicURL,
		encryptionKey:   encryptionKey,
		tokenRateLimit:  tokenRateLimit,
	}
}

func (h *TokenHandler) Handle(w http.ResponseWriter, r *http.Request) {
	// RFC 6749 §5.1 — no-store on token responses.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

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

func (h *TokenHandler) handleAuthorizationCode(w http.ResponseWriter, r *http.Request) {
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

	if allowed, err := h.rateLimitCheck(r.Context(), clientID); err != nil {
		slog.Warn("token: rate limit check failed (allowing)", "error", err)
	} else if !allowed {
		writeTokenError(w, http.StatusTooManyRequests, "invalid_request", "Rate limit exceeded for this client.")
		return
	}

	ok, err := h.clientStore.VerifySecret(r.Context(), h.pool, clientID, clientSecret)
	if err != nil || !ok {
		h.writeBestEffortAudit(r, audit.Event{
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
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Client not found.")
		return
	}

	codeHash := sha256hex([]byte(code))
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Could not begin transaction.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	row, consumeErr := h.codeStore.ConsumeOnce(r.Context(), tx, codeHash)
	if errors.Is(consumeErr, ErrAuthCodeAlreadyUsed) {
		// Replay path opens its own tx — roll back the current one first.
		_ = tx.Rollback(r.Context())
		h.handleCodeReplay(r, w, codeHash)
		return
	}
	if consumeErr != nil {
		slog.Error("token: consume code", "error", consumeErr)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Could not consume authorization code.")
		return
	}

	if row.ClientID != client.ID {
		// Theft indicator — code was issued for a different client. Burned by ConsumeOnce above.
		if auditErr := h.auditStore.Emit(r.Context(), tx, audit.Event{
			EventType:  "oidc.code.client_mismatch",
			ActorID:    &row.UserID,
			ActorEmail: "",
			TargetType: "client",
			TargetID:   client.ID.String(),
			ClientID:   &client.ID,
			IPAddress:  extractClientIP(r),
			Outcome:    "failure",
			Metadata:   map[string]any{"family_id": row.FamilyID.String()},
		}); auditErr != nil {
			slog.Error("token: client_mismatch audit", "error", auditErr)
		}
		if err := tx.Commit(r.Context()); err != nil {
			writeTokenError(w, http.StatusInternalServerError, "server_error", "Could not commit.")
			return
		}
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Code / client mismatch.")
		return
	}

	if row.RedirectURI != redirectURI {
		if auditErr := h.auditStore.Emit(r.Context(), tx, audit.Event{
			EventType:  "oidc.code.redirect_mismatch",
			ActorID:    &row.UserID,
			ActorEmail: "",
			TargetType: "client",
			TargetID:   client.ID.String(),
			ClientID:   &client.ID,
			IPAddress:  extractClientIP(r),
			Outcome:    "failure",
			Metadata:   map[string]any{"family_id": row.FamilyID.String()},
		}); auditErr != nil {
			slog.Error("token: redirect_mismatch audit", "error", auditErr)
		}
		if err := tx.Commit(r.Context()); err != nil {
			writeTokenError(w, http.StatusInternalServerError, "server_error", "Could not commit.")
			return
		}
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch.")
		return
	}

	if !oidc.VerifyPKCE(row.CodeChallenge, codeVerifier) {
		if auditErr := h.auditStore.Emit(r.Context(), tx, audit.Event{
			EventType:  "oidc.code.pkce_mismatch",
			ActorID:    &row.UserID,
			ActorEmail: "",
			TargetType: "client",
			TargetID:   client.ID.String(),
			ClientID:   &client.ID,
			IPAddress:  extractClientIP(r),
			Outcome:    "failure",
			Metadata:   map[string]any{"family_id": row.FamilyID.String()},
		}); auditErr != nil {
			slog.Error("token: pkce_mismatch audit", "error", auditErr)
		}
		if err := tx.Commit(r.Context()); err != nil {
			writeTokenError(w, http.StatusInternalServerError, "server_error", "Could not commit.")
			return
		}
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "PKCE verifier mismatch.")
		return
	}

	u, err := h.userStore.GetByID(r.Context(), tx, row.UserID)
	if err != nil {
		if auditErr := h.auditStore.Emit(r.Context(), tx, audit.Event{
			EventType:  "oidc.code.user_not_found",
			ActorID:    &row.UserID,
			ActorEmail: "",
			TargetType: "client",
			TargetID:   client.ID.String(),
			ClientID:   &client.ID,
			IPAddress:  extractClientIP(r),
			Outcome:    "failure",
			Metadata: map[string]any{
				"family_id": row.FamilyID.String(),
				"user_id":   row.UserID.String(),
			},
		}); auditErr != nil {
			slog.Error("token: user_not_found audit", "error", auditErr)
		}
		if err := tx.Commit(r.Context()); err != nil {
			writeTokenError(w, http.StatusInternalServerError, "server_error", "Could not commit.")
			return
		}
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "User not found.")
		return
	}
	if u.Status != "active" {
		if auditErr := h.auditStore.Emit(r.Context(), tx, audit.Event{
			EventType:  "oidc.code.user_disabled",
			ActorID:    &u.ID,
			ActorEmail: u.Email,
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

	// Re-validate grant type — admin PATCH may have removed
	// authorization_code from allowed_grant_types.
	allowsAuthCode := false
	for _, g := range client.AllowedGrantTypes {
		if g == "authorization_code" {
			allowsAuthCode = true
			break
		}
	}
	if !allowsAuthCode {
		if auditErr := h.auditStore.Emit(r.Context(), tx, audit.Event{
			EventType:  "oidc.code.grant_removed",
			ActorID:    &u.ID,
			ActorEmail: u.Email,
			TargetType: "client",
			TargetID:   client.ID.String(),
			ClientID:   &client.ID,
			IPAddress:  extractClientIP(r),
			Outcome:    "failure",
			Metadata:   map[string]any{"family_id": row.FamilyID.String()},
		}); auditErr != nil {
			slog.Error("token: grant_removed audit", "error", auditErr)
		}
		if err := tx.Commit(r.Context()); err != nil {
			writeTokenError(w, http.StatusInternalServerError, "server_error", "Could not commit.")
			return
		}
		writeTokenError(w, http.StatusBadRequest, "unauthorized_client", "authorization_code grant no longer allowed for this client")
		return
	}

	narrowedCodeScopes, err := intersectScopesAgainstClient(row.Scopes, client.AllowedScopes)
	if err != nil {
		if auditErr := h.auditStore.Emit(r.Context(), tx, audit.Event{
			EventType:  "oidc.code.scope_removed",
			ActorID:    &u.ID,
			ActorEmail: u.Email,
			TargetType: "client",
			TargetID:   client.ID.String(),
			ClientID:   &client.ID,
			IPAddress:  extractClientIP(r),
			Outcome:    "failure",
			Metadata: map[string]any{
				"family_id":        row.FamilyID.String(),
				"requested_scopes": row.Scopes,
				"allowed_scopes":   client.AllowedScopes,
			},
		}); auditErr != nil {
			slog.Error("token: scope_removed audit", "error", auditErr)
		}
		if err := tx.Commit(r.Context()); err != nil {
			writeTokenError(w, http.StatusInternalServerError, "server_error", "Could not commit.")
			return
		}
		writeTokenError(w, http.StatusBadRequest, "invalid_scope", "requested scopes no longer allowed for this client")
		return
	}

	accessTTL, refreshTTL, err := h.readTokenTTLs(r.Context(), tx)
	if err != nil {
		slog.Error("token: readTokenTTLs", "error", err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Could not read token TTLs.")
		return
	}

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

	now := time.Now().UTC()
	scopes := oidc.Scopes(narrowedCodeScopes)
	jtiAccess := uuid.NewString()
	accessClaims := oidc.BuildAccessClaims(u, client.ID.String(), h.publicURL, jtiAccess, scopes, now, accessTTL)
	accessTok, err := oidc.SignAccessToken(accessClaims, activeKey.ID.String(), privPEM)
	if err != nil {
		slog.Error("token: sign access token", "error", err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Signing failed.")
		return
	}

	// auth_time approximation: code was minted 60s before ExpiresAt. Precise
	// value requires plumbing session data from /authorize (not in v1).
	authTime := row.ExpiresAt.Add(-authCodeTTL)
	nonce := ""
	if row.Nonce != nil {
		nonce = *row.Nonce
	}
	jtiID := uuid.NewString()
	idClaims := oidc.BuildIDClaims(u, client.ID.String(), h.publicURL, jtiID, nonce, scopes, authTime, now, accessTTL)
	idTok, err := oidc.SignIDToken(idClaims, activeKey.ID.String(), privPEM)
	if err != nil {
		slog.Error("token: sign id token", "error", err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Signing failed.")
		return
	}

	var refreshTokenStr string
	if scopes.Has("offline_access") {
		tok, err := h.refreshStore.Create(r.Context(), oidc.RefreshPayload{
			UserID:    u.ID.String(),
			ClientID:  client.ID.String(),
			Scopes:    narrowedCodeScopes,
			FamilyID:  row.FamilyID.String(),
			CreatedAt: now.Unix(),
			Expires:   now.Add(refreshTTL).Unix(),
		})
		if err != nil {
			slog.Error("token: refresh create", "error", err)
			writeTokenError(w, http.StatusInternalServerError, "server_error", "Could not mint refresh token.")
			return
		}
		refreshTokenStr = tok
	}

	if err := h.auditStore.Emit(r.Context(), tx, audit.Event{
		EventType:  "oidc.code.exchanged",
		ActorID:    &u.ID,
		ActorEmail: u.Email,
		TargetType: "client",
		TargetID:   client.ID.String(),
		ClientID:   &client.ID,
		IPAddress:  extractClientIP(r),
		Outcome:    "success",
		Metadata: map[string]any{
			"family_id":      row.FamilyID.String(),
			"scopes":         narrowedCodeScopes,
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

	resp := tokenResponse{
		AccessToken:  accessTok,
		TokenType:    "Bearer",
		ExpiresIn:    int(accessTTL.Seconds()),
		RefreshToken: refreshTokenStr,
		IDToken:      idTok,
		Scope:        scopes.String(),
	}
	httputil.WriteJSON(w, http.StatusOK, resp)
}

// handleCodeReplay revokes the refresh-token family tied to the already-used
// code (OAuth 2.1 §4.1.3) and audits oidc.code.replay_detected.
func (h *TokenHandler) handleCodeReplay(r *http.Request, w http.ResponseWriter, codeHash string) {
	familyID, err := h.codeStore.LookupFamilyByCodeHash(r.Context(), h.pool, codeHash)
	if err != nil {
		slog.Error("token: LookupFamilyByCodeHash on replay", "error", err)
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Code already used.")
		return
	}
	if err := h.refreshStore.RevokeFamily(r.Context(), familyID.String()); err != nil {
		slog.Error("token: RevokeFamily on replay", "error", err)
	}

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("token: replay audit begin", "error", err)
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Code already used.")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	if err := h.auditStore.Emit(r.Context(), tx, audit.Event{
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

// rateLimitCheck: fixed 60-second window per client_id.
func (h *TokenHandler) rateLimitCheck(ctx context.Context, clientID string) (bool, error) {
	key := "ratelimit:oidc:token:" + clientID
	count, err := h.valkey.Incr(ctx, key).Result()
	if err != nil {
		return true, err
	}
	if count == 1 {
		_ = h.valkey.Expire(ctx, key, time.Minute).Err()
	}
	return count <= h.tokenRateLimit, nil
}

func (h *TokenHandler) readTokenTTLs(ctx context.Context, q database.Querier) (access, refresh time.Duration, err error) {
	accessSecs, err := h.instanceConfig.AccessTokenTTLSecs(ctx, q)
	if err != nil {
		return 0, 0, err
	}
	refreshSecs, err := h.instanceConfig.RefreshTokenTTLSecs(ctx, q)
	if err != nil {
		return 0, 0, err
	}
	return time.Duration(accessSecs) * time.Second, time.Duration(refreshSecs) * time.Second, nil
}

func (h *TokenHandler) writeBestEffortAudit(r *http.Request, event audit.Event) {
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("token best-effort audit: begin", "error", err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	if err := h.auditStore.Emit(r.Context(), tx, event); err != nil {
		slog.Error("token best-effort audit: emit", "error", err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("token best-effort audit: commit", "error", err)
	}
}

// handleRefreshToken: OAuth 2.1 §6 rotate-on-every-use. Each rotation
// shares the original family_id and preserves absolute expiry from the
// initial code exchange — passing oldPayload.Expires means TTL = exp-now,
// NOT now+24h.
func (h *TokenHandler) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
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

	if allowed, err := h.rateLimitCheck(r.Context(), clientID); err != nil {
		slog.Warn("token refresh: rate limit check failed (allowing)", "error", err)
	} else if !allowed {
		writeTokenError(w, http.StatusTooManyRequests, "invalid_request", "Rate limit exceeded for this client.")
		return
	}

	ok, err := h.clientStore.VerifySecret(r.Context(), h.pool, clientID, clientSecret)
	if err != nil || !ok {
		h.writeBestEffortAudit(r, audit.Event{
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

	oldPayload, consumeErr := h.refreshStore.Consume(r.Context(), presentedRefresh)
	if errors.Is(consumeErr, oidc.ErrRefreshUnknownOrExpired) {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Refresh token invalid or expired.")
		return
	}
	if errors.Is(consumeErr, oidc.ErrRefreshReuseDetected) {
		// OAuth 2.1 §4.13: presented token was already rotated — revoke the
		// entire family. Valkey revoke is the authoritative guard.
		if oldPayload != nil {
			if err := h.refreshStore.RevokeFamily(r.Context(), oldPayload.FamilyID); err != nil {
				slog.Error("token refresh: RevokeFamily on reuse", "error", err)
			}
			h.writeBestEffortAudit(r, audit.Event{
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

	if oldPayload.ClientID != client.ID.String() {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Refresh / client mismatch.")
		return
	}

	allowsRefresh := false
	for _, g := range client.AllowedGrantTypes {
		if g == "refresh_token" {
			allowsRefresh = true
			break
		}
	}
	if !allowsRefresh {
		writeTokenError(w, http.StatusBadRequest, "unauthorized_client", "refresh_token grant no longer allowed for this client")
		return
	}

	narrowedScopes, err := intersectScopesAgainstClient(oldPayload.Scopes, client.AllowedScopes)
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_scope", "requested scopes no longer allowed for this client")
		return
	}

	userUUID, err := uuid.Parse(oldPayload.UserID)
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Refresh payload malformed.")
		return
	}
	u, err := h.userStore.GetByID(r.Context(), h.pool, userUUID)
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "User not found.")
		return
	}
	if u.Status != "active" {
		if err := h.refreshStore.RevokeFamily(r.Context(), oldPayload.FamilyID); err != nil {
			slog.Error("token refresh: RevokeFamily on disabled-user", "error", err)
		}
		h.writeBestEffortAudit(r, audit.Event{
			EventType:  "oidc.refresh.user_disabled",
			ActorID:    &u.ID,
			ActorEmail: u.Email,
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

	// revoke_before: reject if the refresh was issued before the cutoff.
	// Anchored on the refresh's CreatedAt; access tokens derived from it
	// inherit the same provenance. Fail-open on transport errors — a Valkey
	// blip must not revoke all active sessions.
	rbCutoff, rbErr := session.RevokeBeforeGet(r.Context(), h.valkey, u.ID.String())
	if rbErr == nil && oldPayload.CreatedAt < rbCutoff.Unix() {
		if rerr := h.refreshStore.RevokeFamily(r.Context(), oldPayload.FamilyID); rerr != nil {
			slog.Error("token refresh: RevokeFamily on revoke_before", "error", rerr)
		}
		h.writeBestEffortAudit(r, audit.Event{
			EventType:  "user.revoke_before_enforced",
			ActorID:    &u.ID,
			ActorEmail: u.Email,
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
	if rbErr != nil && rbErr != session.ErrRevokeBeforeNotSet {
		slog.Warn("token refresh: revoke_before Get failed (allowing)", "error", rbErr)
	}

	accessTTL, _, err := h.readTokenTTLs(r.Context(), h.pool)
	if err != nil {
		slog.Error("token refresh: readTokenTTLs", "error", err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Could not read token TTLs.")
		return
	}

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

	now := time.Now().UTC()
	scopes := oidc.Scopes(narrowedScopes)
	jtiAccess := uuid.NewString()
	jtiID := uuid.NewString()
	accessClaims := oidc.BuildAccessClaims(u, client.ID.String(), h.publicURL, jtiAccess, scopes, now, accessTTL)
	accessTok, err := oidc.SignAccessToken(accessClaims, activeKey.ID.String(), privPEM)
	if err != nil {
		slog.Error("token refresh: sign access", "error", err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Signing failed.")
		return
	}
	// auth_time is not re-derivable at refresh time; use refresh's CreatedAt
	// as a floor.
	authTime := time.Unix(oldPayload.CreatedAt, 0).UTC()
	idClaims := oidc.BuildIDClaims(u, client.ID.String(), h.publicURL, jtiID, "", scopes, authTime, now, accessTTL)
	idTok, err := oidc.SignIDToken(idClaims, activeKey.ID.String(), privPEM)
	if err != nil {
		slog.Error("token refresh: sign id", "error", err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Signing failed.")
		return
	}

	newRefresh, err := h.refreshStore.Create(r.Context(), oidc.RefreshPayload{
		UserID:    u.ID.String(),
		ClientID:  client.ID.String(),
		Scopes:    narrowedScopes,
		FamilyID:  oldPayload.FamilyID,
		CreatedAt: now.Unix(),
		Expires:   oldPayload.Expires, // absolute; preserves 24h ceiling
	})
	if err != nil {
		slog.Warn("token refresh: Create rotated refresh failed", "error", err)
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Refresh token expired.")
		return
	}

	// MarkUsed ordering: Create runs first so the RP always gets usable
	// tokens even if MarkUsed fails. A duplicate rotation window exists if
	// MarkUsed fails, but family_id linkage means a future reuse attack on
	// either copy still triggers RevokeFamily. Preferable to aborting the
	// response on a MarkUsed failure.
	if err := h.refreshStore.MarkUsed(r.Context(), presentedRefresh); err != nil {
		slog.Error("token refresh: MarkUsed old token", "error", err, "family_id", oldPayload.FamilyID) //nolint:gosec // G706: slog structured logging is not susceptible to log injection
	}

	// `oidc.token.refreshed` is intentionally NOT emitted: a successful
	// refresh is bookkeeping (session-lifetime extension). The forensically
	// valuable failure variants — `oidc.refresh.reuse_detected` (token theft
	// signal) and `oidc.refresh.user_disabled` — remain audited at their own
	// emit sites earlier in this function.

	httputil.WriteJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  accessTok,
		TokenType:    "Bearer",
		ExpiresIn:    int(accessTTL.Seconds()),
		RefreshToken: newRefresh,
		IDToken:      idTok,
		Scope:        scopes.String(),
	})
}

func uuidPtr(s string) *uuid.UUID {
	u, err := uuid.Parse(s)
	if err != nil {
		return nil
	}
	return &u
}

// writeTokenError writes an RFC 6749 §5.2 error response.
func writeTokenError(w http.ResponseWriter, status int, oauthErr, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             oauthErr,
		"error_description": description,
	})
}
