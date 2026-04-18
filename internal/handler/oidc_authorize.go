package handler

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdo75/Schlass/internal/middleware"
	"github.com/abdo75/Schlass/internal/oidc"
	"github.com/abdo75/Schlass/internal/session"
	"github.com/abdo75/Schlass/internal/store"
)

const authCodeTTL = 60 * time.Second

// OIDCAuthorizeHandler serves GET /authorize. Flow:
//  1. Validate client_id + redirect_uri FIRST — failure renders local error.
//  2. Validate other params — failure redirects back to RP with error=.
//  3. Session resolution (OptionalAuth already ran). Handle prompt=none /
//     prompt=login / max_age re-auth. No session → 302 /login?return_to=...
//  4. Mint code + audit in one tx, 302 to RP callback with ?code=&state=.
type OIDCAuthorizeHandler struct {
	pool         *pgxpool.Pool
	clientStore  *store.ClientStore
	codeStore    *store.AuthCodeStore
	auditStore   AuditLogger
	sessionStore session.Store
	publicURL    string
	secureCookie bool
}

func NewOIDCAuthorizeHandler(
	pool *pgxpool.Pool,
	sessionStore session.Store,
	auditStore AuditLogger,
	publicURL string,
) *OIDCAuthorizeHandler {
	return &OIDCAuthorizeHandler{
		pool:         pool,
		clientStore:  store.NewClientStore(),
		codeStore:    store.NewAuthCodeStore(),
		auditStore:   auditStore,
		sessionStore: sessionStore,
		publicURL:    publicURL,
		secureCookie: isSecureURL(publicURL),
	}
}

func (h *OIDCAuthorizeHandler) Handle(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")

	// --- 1. Validate client_id + redirect_uri FIRST.
	//        Failure renders local error (untrusted trigger).
	if clientID == "" || redirectURI == "" {
		h.renderLocalError(r, w, oidc.ErrInvalidRequest("missing client_id or redirect_uri"),
			map[string]any{
				"client_id_raw":    truncate(clientID, 256),
				"redirect_uri_raw": truncate(redirectURI, 1024),
			})
		return
	}
	client, err := h.clientStore.GetByID(r.Context(), h.pool, clientID)
	if err != nil {
		h.renderLocalError(r, w, oidc.ErrInvalidClient("unknown or disabled client"),
			map[string]any{
				"client_id_raw":    truncate(clientID, 256),
				"redirect_uri_raw": truncate(redirectURI, 1024),
			})
		return
	}
	if !h.clientStore.ValidateRedirectURI(client, redirectURI) {
		h.renderLocalError(r, w, oidc.ErrInvalidRedirectURI("redirect_uri not registered for client"),
			map[string]any{
				"client_id":        client.ID.String(),
				"redirect_uri_raw": truncate(redirectURI, 1024),
			})
		return
	}

	// --- 2. Other params. Failures redirect back to trusted RP.
	responseType := q.Get("response_type")
	if responseType != "code" {
		h.redirectError(w, r, redirectURI, q.Get("state"), oidc.ErrUnsupportedResponseType("only 'code' supported"))
		return
	}
	state := q.Get("state")
	if state == "" {
		h.redirectError(w, r, redirectURI, "", oidc.ErrInvalidRequest("state is required"))
		return
	}
	codeChallenge := q.Get("code_challenge")
	method := q.Get("code_challenge_method")
	if codeChallenge == "" || method != "S256" {
		h.redirectError(w, r, redirectURI, state, oidc.ErrInvalidRequest("PKCE S256 required"))
		return
	}

	// Scope: default to "openid profile" when absent.
	scopesStr := q.Get("scope")
	if scopesStr == "" {
		scopesStr = "openid profile"
	}
	scopes := strings.Fields(scopesStr)
	if !containsString(scopes, "openid") {
		h.redirectError(w, r, redirectURI, state, oidc.ErrInvalidScope("openid scope required"))
		return
	}
	for _, sc := range scopes {
		if !containsString(client.AllowedScopes, sc) {
			h.redirectError(w, r, redirectURI, state, oidc.ErrInvalidScope("scope not allowed for client: "+sc))
			return
		}
	}

	// Prompt.
	prompt := q.Get("prompt")
	if strings.Contains(prompt, " ") {
		h.redirectError(w, r, redirectURI, state, oidc.ErrInvalidRequest("combined prompt values not supported"))
		return
	}
	if prompt != "" && prompt != "none" && prompt != "login" {
		h.redirectError(w, r, redirectURI, state, oidc.ErrInvalidRequest("unsupported prompt value"))
		return
	}

	// max_age (seconds). Cap at math.MaxInt64/int64(time.Second) to avoid
	// overflow when converting uint64 → time.Duration (int64 nanoseconds).
	const maxAgeCap uint64 = uint64(1<<63-1) / uint64(time.Second)
	var maxAge time.Duration
	if ma := q.Get("max_age"); ma != "" {
		secs, perr := parseUint(ma)
		if perr != nil {
			h.redirectError(w, r, redirectURI, state, oidc.ErrInvalidRequest("max_age invalid"))
			return
		}
		if secs > maxAgeCap {
			secs = maxAgeCap
		}
		maxAge = time.Duration(secs) * time.Second //nolint:gosec // bounded by maxAgeCap above
	}

	// --- 3. Session resolution (OptionalAuth already ran).
	user, _ := middleware.CurrentUser(r.Context())

	needReauth := user == nil || prompt == "login"
	if !needReauth && maxAge > 0 {
		sess, serr := h.getSessionFromCookie(r)
		if serr == nil && time.Since(sess.CreatedAt) > maxAge {
			needReauth = true
		}
	}

	if needReauth {
		if prompt == "none" {
			h.redirectError(w, r, redirectURI, state, oidc.ErrLoginRequired())
			return
		}
		// Clear existing session if any + audit session.reauth_forced.
		if user != nil {
			if cookie, cerr := r.Cookie("schlass_session"); cerr == nil {
				_ = h.sessionStore.Delete(r.Context(), user.ID.String(), cookie.Value)
			}
			h.writeBestEffortAudit(r, store.AuditEntry{
				EventType:  "session.reauth_forced",
				ActorID:    &user.ID,
				ActorEmail: user.Email,
				TargetType: "user",
				TargetID:   user.ID.String(),
				IPAddress:  extractClientIP(r),
				Outcome:    "success",
				Metadata:   map[string]any{"reason": "oidc_" + nonEmpty(prompt, "max_age")},
			})
			clearAuthorizeSessionCookie(w, h.secureCookie)
		}
		returnTo := url.QueryEscape(r.URL.Path + "?" + r.URL.RawQuery)
		http.Redirect(w, r, "/login?return_to="+returnTo, http.StatusFound)
		return
	}

	// --- 4. Mint code + audit in one tx.
	rawCodeBuf := make([]byte, 32)
	if _, err := rand.Read(rawCodeBuf); err != nil {
		h.redirectError(w, r, redirectURI, state, oidc.ErrServerError("entropy"))
		return
	}
	rawCode := base64.RawURLEncoding.EncodeToString(rawCodeBuf)
	codeHash := sha256hex([]byte(rawCode))
	familyID := uuid.New()

	var noncePtr *string
	if n := q.Get("nonce"); n != "" {
		noncePtr = &n
	}

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		h.redirectError(w, r, redirectURI, state, oidc.ErrServerError("db begin"))
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	if err := h.codeStore.Insert(r.Context(), tx, store.AuthCodeRow{
		CodeHash:            codeHash,
		ClientID:            client.ID,
		UserID:              user.ID,
		RedirectURI:         redirectURI,
		Scopes:              scopes,
		Nonce:               noncePtr,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: method,
		ExpiresAt:           time.Now().Add(authCodeTTL),
		FamilyID:            familyID,
	}); err != nil {
		slog.Error("authorize: insert code", "error", err)
		h.redirectError(w, r, redirectURI, state, oidc.ErrServerError("db insert"))
		return
	}
	if err := h.auditStore.Log(r.Context(), tx, store.AuditEntry{
		EventType:  "oidc.authorize.succeeded",
		ActorID:    &user.ID,
		ActorEmail: user.Email,
		TargetType: "client",
		TargetID:   client.ID.String(),
		IPAddress:  extractClientIP(r),
		Outcome:    "success",
		Metadata: map[string]any{
			"scopes":    scopes,
			"family_id": familyID.String(),
		},
	}); err != nil {
		slog.Error("authorize: audit", "error", err)
		h.redirectError(w, r, redirectURI, state, oidc.ErrServerError("audit"))
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		h.redirectError(w, r, redirectURI, state, oidc.ErrServerError("commit"))
		return
	}

	// 302 to RP callback.
	v := url.Values{}
	v.Set("code", rawCode)
	v.Set("state", state)
	dest := redirectURI
	if strings.Contains(dest, "?") {
		dest += "&" + v.Encode()
	} else {
		dest += "?" + v.Encode()
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

// renderLocalError writes a best-effort audit row with a correlation ID and
// 302s to /oidc/error?ref=<corrid>. The SPA page at /oidc/error renders the
// user-visible message; we only drop a marker + audit trail here.
//
// Metadata key is error_ref (not correlation_id) because audit_store.Log
// already reserves "correlation_id" for the HTTP request trace ID injected
// by middleware.RequestLogging. Admins look up local-error events via
// metadata->>'error_ref' = $1 using the ref value the user reported.
func (h *OIDCAuthorizeHandler) renderLocalError(r *http.Request, w http.ResponseWriter, ae *oidc.AuthorizeError, extra map[string]any) {
	corrID, cerr := oidc.NewCorrelationID()
	if cerr != nil {
		corrID = "err_unknown"
	}
	md := map[string]any{
		"error_ref":   corrID,
		"oauth_error": ae.Code,
		"reason":      ae.Description,
		"user_agent":  truncate(r.Header.Get("User-Agent"), 512),
	}
	for k, v := range extra {
		md[k] = v
	}
	h.writeBestEffortAudit(r, store.AuditEntry{
		EventType:  "oidc.authorize.invalid_request",
		ActorEmail: "",
		TargetType: "authorize_request",
		IPAddress:  extractClientIP(r),
		Outcome:    "failure",
		Metadata:   md,
	})
	http.Redirect(w, r, "/oidc/error?ref="+corrID, http.StatusFound)
}

// redirectError bounces back to the registered redirect_uri with OAuth
// error query params. Used when client_id + redirect_uri are trusted.
func (h *OIDCAuthorizeHandler) redirectError(w http.ResponseWriter, r *http.Request, redirectURI, state string, ae *oidc.AuthorizeError) {
	v := url.Values{}
	v.Set("error", ae.Code)
	if ae.Description != "" {
		v.Set("error_description", ae.Description)
	}
	if state != "" {
		v.Set("state", state)
	}
	dest := redirectURI
	if strings.Contains(dest, "?") {
		dest += "&" + v.Encode()
	} else {
		dest += "?" + v.Encode()
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

func (h *OIDCAuthorizeHandler) getSessionFromCookie(r *http.Request) (*session.Session, error) {
	c, err := r.Cookie("schlass_session")
	if err != nil {
		return nil, err
	}
	return h.sessionStore.Get(r.Context(), c.Value)
}

// writeBestEffortAudit persists an audit row in its own tx. Failure is
// slog.Error'd but does not block the caller — matches the middleware
// session.revoked pattern.
func (h *OIDCAuthorizeHandler) writeBestEffortAudit(r *http.Request, entry store.AuditEntry) {
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("authorize audit: begin", "error", err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	if err := h.auditStore.Log(r.Context(), tx, entry); err != nil {
		slog.Error("authorize audit: log", "error", err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("authorize audit: commit", "error", err)
	}
}

// Ensure errors package is used (kept here so future callers of errors.Is stay clean).
var _ = errors.New

// --- tiny helpers local to this file

func containsString(slice []string, want string) bool {
	for _, v := range slice {
		if v == want {
			return true
		}
	}
	return false
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max]
	}
	return s
}

func parseUint(s string) (uint64, error) {
	if s == "" {
		return 0, errors.New("empty")
	}
	var n uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("not a uint")
		}
		n = n*10 + uint64(c-'0')
	}
	return n, nil
}

func sha256hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func nonEmpty(a, fallback string) string {
	if a != "" {
		return a
	}
	return fallback
}

func clearAuthorizeSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     "schlass_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   secure,
		MaxAge:   -1,
	})
}
