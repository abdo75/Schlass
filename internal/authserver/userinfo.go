package authserver

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdo75/Schlass/internal/audit"
	"github.com/abdo75/Schlass/internal/httputil"
	"github.com/abdo75/Schlass/internal/oidc"
	"github.com/abdo75/Schlass/internal/users"
)

// UserInfoHandler serves GET /userinfo behind BearerAuth.
// Response is plain JSON (not a JWT) — OIDC Core §5.3 allows either.
type UserInfoHandler struct {
	pool       *pgxpool.Pool
	auditStore audit.Logger
}

func NewUserInfoHandler(pool *pgxpool.Pool, auditStore audit.Logger) *UserInfoHandler {
	return &UserInfoHandler{pool: pool, auditStore: auditStore}
}

func (h *UserInfoHandler) Handle(w http.ResponseWriter, r *http.Request) {
	user, ok := users.CurrentUser(r.Context())
	if !ok {
		slog.Error("userinfo: no user in context (middleware wiring bug)")
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}
	claims, ok := CurrentBearerClaims(r.Context())
	if !ok {
		slog.Error("userinfo: no bearer claims in context")
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	scopes := oidc.Scopes(strings.Fields(claims.Scope))
	body := oidc.BuildUserInfoClaims(user, scopes)

	// Best-effort audit — high-volume event, must not block the response.
	_ = h.writeBestEffortAudit(r, audit.Entry{
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

	httputil.WriteJSON(w, http.StatusOK, body)
}

func (h *UserInfoHandler) writeBestEffortAudit(r *http.Request, entry audit.Entry) error {
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
