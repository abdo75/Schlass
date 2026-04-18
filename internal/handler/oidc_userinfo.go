package handler

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdo75/Schlass/internal/middleware"
	"github.com/abdo75/Schlass/internal/oidc"
	"github.com/abdo75/Schlass/internal/store"
)

// OIDCUserInfoHandler serves GET /userinfo. Behind middleware.BearerAuth,
// so the user + parsed access-token claims are already in the request
// context by the time Handle runs.
//
// Response shape: plain JSON (not a JWT). OIDC Core §5.3 allows either;
// we choose JSON since no RP library we target requires signed userinfo.
type OIDCUserInfoHandler struct {
	pool       *pgxpool.Pool
	auditStore AuditLogger
}

func NewOIDCUserInfoHandler(pool *pgxpool.Pool, auditStore AuditLogger) *OIDCUserInfoHandler {
	return &OIDCUserInfoHandler{pool: pool, auditStore: auditStore}
}

func (h *OIDCUserInfoHandler) Handle(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.CurrentUser(r.Context())
	if !ok {
		// Middleware wiring bug — BearerAuth should have gated this route.
		slog.Error("userinfo: no user in context (middleware wiring bug)")
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	claims, ok := middleware.CurrentBearerClaims(r.Context())
	if !ok {
		slog.Error("userinfo: no bearer claims in context")
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	scopes := oidc.Scopes(strings.Fields(claims.Scope))
	body := oidc.BuildUserInfoClaims(user, scopes)

	// Best-effort audit — high-volume event (every token-holding request).
	// Never blocks the response on audit failure. Matches the documented
	// exception pattern in CLAUDE.md / spec §K.
	// Already logged inside writeBestEffortAudit on failure; swallow here.
	_ = h.writeBestEffortAudit(r, store.AuditEntry{
		EventType:  "oidc.userinfo.accessed",
		ActorID:    &user.ID,
		ActorEmail: user.Email,
		TargetType: "client",
		TargetID:   claims.Audience,
		IPAddress:  extractClientIP(r),
		Outcome:    "success",
		Metadata: map[string]any{
			"scopes": strings.Fields(claims.Scope),
			"jti":    claims.JTI,
		},
	})

	writeJSON(w, http.StatusOK, body)
}

// writeBestEffortAudit persists an audit row in its own tx. Failure is logged
// but does not block the caller. Mirrors the pattern used by /token and /authorize.
func (h *OIDCUserInfoHandler) writeBestEffortAudit(r *http.Request, entry store.AuditEntry) error {
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		slog.Error("userinfo best-effort audit: begin", "error", err)
		return err
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	if err := h.auditStore.Log(r.Context(), tx, entry); err != nil {
		slog.Error("userinfo best-effort audit: log", "error", err)
		return err
	}
	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("userinfo best-effort audit: commit", "error", err)
		return err
	}
	return nil
}
