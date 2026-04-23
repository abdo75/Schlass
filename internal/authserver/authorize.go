package authserver

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

	"github.com/abdo75/Schlass/internal/audit"
	"github.com/abdo75/Schlass/internal/clients"
	"github.com/abdo75/Schlass/internal/oidc"
	"github.com/abdo75/Schlass/internal/session"
	"github.com/abdo75/Schlass/internal/users"
)

const authCodeTTL = 60 * time.Second

// AuthorizeHandler serves GET /authorize. client_id + redirect_uri are
// validated FIRST (local-error render) so failures don't bounce to an
// untrusted URL; other param failures redirect back to the now-trusted RP.
type AuthorizeHandler struct {
	pool         *pgxpool.Pool
	clientStore  *clients.Store
	codeStore    *AuthCodeStore
	auditStore   audit.Logger
	sessionStore session.Store
	publicURL    string
	secureCookie bool
}

func NewAuthorizeHandler(
	pool *pgxpool.Pool,
	sessionStore session.Store,
	auditStore audit.Logger,
	publicURL string,
) *AuthorizeHandler {
	return &AuthorizeHandler{
		pool:         pool,
		clientStore:  clients.NewStore(),
		codeStore:    NewAuthCodeStore(),
		auditStore:   auditStore,
		sessionStore: sessionStore,
		publicURL:    publicURL,
		secureCookie: session.IsSecureURL(publicURL),
	}
}

func (h *AuthorizeHandler) Handle(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")

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

	prompt := q.Get("prompt")
	if strings.Contains(prompt, " ") {
		h.redirectError(w, r, redirectURI, state, oidc.ErrInvalidRequest("combined prompt values not supported"))
		return
	}
	if prompt != "" && prompt != "none" && prompt != "login" {
		h.redirectError(w, r, redirectURI, state, oidc.ErrInvalidRequest("unsupported prompt value"))
		return
	}

	// max_age capped to avoid overflow converting uint64 → int64 ns Duration.
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

	user, _ := users.CurrentUser(r.Context())

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
		if user != nil {
			if cookie, cerr := r.Cookie("schlass_session"); cerr == nil {
				_ = h.sessionStore.Delete(r.Context(), user.ID.String(), cookie.Value)
			}
			h.writeBestEffortAudit(r, audit.Entry{
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

	if err := h.codeStore.Insert(r.Context(), tx, AuthCodeRow{
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
	if err := h.auditStore.Log(r.Context(), tx, audit.Entry{
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

// renderLocalError writes a best-effort audit row with a correlation ID
// (metadata key error_ref — correlation_id is reserved for the request
// trace ID) and 302s to /oidc/error?ref=<corrid>. The SPA page renders the
// message; we only drop a marker + audit trail.
func (h *AuthorizeHandler) renderLocalError(r *http.Request, w http.ResponseWriter, ae *oidc.AuthorizeError, extra map[string]any) {
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
	h.writeBestEffortAudit(r, audit.Entry{
		EventType:  "oidc.authorize.invalid_request",
		ActorEmail: "",
		TargetType: "authorize_request",
		IPAddress:  extractClientIP(r),
		Outcome:    "failure",
		Metadata:   md,
	})
	http.Redirect(w, r, "/oidc/error?ref="+corrID, http.StatusFound)
}

func (h *AuthorizeHandler) redirectError(w http.ResponseWriter, r *http.Request, redirectURI, state string, ae *oidc.AuthorizeError) {
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

func (h *AuthorizeHandler) getSessionFromCookie(r *http.Request) (*session.Session, error) {
	c, err := r.Cookie("schlass_session")
	if err != nil {
		return nil, err
	}
	return h.sessionStore.Get(r.Context(), c.Value)
}

// writeBestEffortAudit: own tx, failure logged but does not block the
// caller. Matches the middleware session.revoked pattern.
func (h *AuthorizeHandler) writeBestEffortAudit(r *http.Request, entry audit.Entry) {
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

var _ = errors.New

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
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
		MaxAge:   -1,
	})
}
