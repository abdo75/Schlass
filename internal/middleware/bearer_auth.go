package middleware

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/abdo75/Schlass/internal/oidc"
	"github.com/abdo75/Schlass/internal/revokebefore"
	"github.com/abdo75/Schlass/internal/store"
)

type bearerClaimsCtxKey struct{}

// ±30s tolerance on exp/nbf — spec §5h; accommodates NTP drift.
const bearerClockSkew = 30 * time.Second

type BearerAuthDeps struct {
	Pool            *pgxpool.Pool
	UserStore       *store.UserStore
	SigningKeyStore *store.SigningKeyStore
	Valkey          *redis.Client
	Issuer          string
}

// BearerAuth — 401 + WWW-Authenticate: Bearer per RFC 6750 §3.1 on any
// failure. Best-effort oidc.userinfo.accessed audit is emitted by the
// handler, not here, so this middleware stays free of audit/tx concerns.
func BearerAuth(d BearerAuthDeps) func(http.Handler) http.Handler {
	if d.SigningKeyStore == nil {
		d.SigningKeyStore = store.NewSigningKeyStore()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := extractBearerToken(r.Header.Get("Authorization"))
			if raw == "" {
				writeBearerError(w, http.StatusUnauthorized, "invalid_token", "Bearer token missing")
				return
			}

			lookup := func(kid string) ([]byte, error) {
				keys, err := d.SigningKeyStore.ListPublishable(r.Context(), d.Pool)
				if err != nil {
					return nil, err
				}
				for _, k := range keys {
					if k.ID.String() == kid {
						return k.PublicKeyPEM, nil
					}
				}
				return nil, fmt.Errorf("kid %s not in JWKS", kid)
			}

			claims, err := oidc.ParseAndVerifyAccessToken(raw, lookup)
			if err != nil {
				writeBearerError(w, http.StatusUnauthorized, "invalid_token", "signature or header invalid")
				return
			}

			now := time.Now().Unix()
			if claims.Issuer != d.Issuer {
				writeBearerError(w, http.StatusUnauthorized, "invalid_token", "issuer mismatch")
				return
			}
			if claims.Audience == "" {
				writeBearerError(w, http.StatusUnauthorized, "invalid_token", "audience missing")
				return
			}
			if claims.Expires > 0 && now > claims.Expires+int64(bearerClockSkew.Seconds()) {
				writeBearerError(w, http.StatusUnauthorized, "invalid_token", "token expired")
				return
			}
			if claims.NotBefore > 0 && now+int64(bearerClockSkew.Seconds()) < claims.NotBefore {
				writeBearerError(w, http.StatusUnauthorized, "invalid_token", "token not yet valid")
				return
			}

			userID, err := uuid.Parse(claims.Subject)
			if err != nil {
				writeBearerError(w, http.StatusUnauthorized, "invalid_token", "subject not a UUID")
				return
			}
			user, err := d.UserStore.GetByID(r.Context(), d.Pool, userID)
			if err != nil {
				if err == store.ErrUserNotFound {
					writeBearerError(w, http.StatusUnauthorized, "invalid_token", "user no longer exists")
					return
				}
				slog.Error("bearer auth: GetByID", "error", err)
				writeBearerError(w, http.StatusInternalServerError, "server_error", "lookup failed")
				return
			}
			if user.Status != "active" {
				writeBearerError(w, http.StatusUnauthorized, "invalid_token", "user not active")
				return
			}

			// revoke_before (spec §5g). Fail-open on transport errors —
			// degraded Valkey must not log out all active users.
			if d.Valkey != nil {
				cutoff, rbErr := revokebefore.Get(r.Context(), d.Valkey, user.ID.String())
				if rbErr == nil && claims.IssuedAt < cutoff.Unix() {
					writeBearerError(w, http.StatusUnauthorized, "invalid_token", "token revoked")
					return
				}
				if rbErr != nil && rbErr != revokebefore.ErrNotSet {
					slog.Warn("bearer auth: revoke_before Get failed (allowing)", "error", rbErr)
				}
			}

			// Per-client revoke_before — DELETE /api/clients/:id writes this
			// so outstanding ATs for a deleted client die immediately.
			// Fail-open policy matches user cutoff.
			if d.Valkey != nil && claims.Audience != "" {
				clientCutoff, cbErr := revokebefore.ClientGet(r.Context(), d.Valkey, claims.Audience)
				if cbErr == nil && claims.IssuedAt < clientCutoff.Unix() {
					writeBearerError(w, http.StatusUnauthorized, "invalid_token", "token revoked by client mutation")
					return
				}
				if cbErr != nil && cbErr != revokebefore.ErrNotSet {
					slog.Warn("bearer auth: client revoke_before Get failed (allowing)", "error", cbErr)
				}
			}

			ctx := context.WithValue(r.Context(), userCtxKey, user)
			ctx = context.WithValue(ctx, bearerClaimsCtxKey{}, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func CurrentBearerClaims(ctx context.Context) (*oidc.AccessTokenClaims, bool) {
	c, ok := ctx.Value(bearerClaimsCtxKey{}).(*oidc.AccessTokenClaims)
	return c, ok
}

func extractBearerToken(header string) string {
	if header == "" {
		return ""
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

// writeBearerError — RFC 6750 §3.1. description must not contain quotes or backslashes.
func writeBearerError(w http.ResponseWriter, status int, oauthErr, description string) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error=%q, error_description=%q`, oauthErr, description))
	writeAuthError(w, status, strings.ToUpper(oauthErr), description)
}
