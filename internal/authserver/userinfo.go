package authserver

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdo75/Schlass/internal/httputil"
	"github.com/abdo75/Schlass/internal/oidc"
	"github.com/abdo75/Schlass/internal/users"
)

// UserInfoHandler serves GET /userinfo behind BearerAuth.
// Response is plain JSON (not a JWT) — OIDC Core §5.3 allows either.
type UserInfoHandler struct {
	pool *pgxpool.Pool
}

func NewUserInfoHandler(pool *pgxpool.Pool) *UserInfoHandler {
	return &UserInfoHandler{pool: pool}
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

	// Successful userinfo reads are not audited: ISO 27001:2022 A.8.15 / NIST
	// 800-53 AU-2 only mandate logging access to security-relevant or
	// sensitive objects, not routine self-reads of OIDC userinfo. Failure
	// paths above (token validation, scope check) emit their own events.

	httputil.WriteJSON(w, http.StatusOK, body)
}

