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

// OIDCUserInfoHandler serves GET /userinfo behind middleware.BearerAuth.
// Response is plain JSON (not a JWT) — OIDC Core §5.3 allows either.
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

	// Best-effort audit — high-volume event, must not block the response.
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
