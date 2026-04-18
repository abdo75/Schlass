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

// bearerClaimsCtxKey stores the parsed access-token claims alongside the user.
// Separate from userCtxKey so BearerAuth is self-contained and cannot be
// confused with the opaque-session Auth middleware.
type bearerClaimsCtxKey struct{}

// bearerClockSkew is the tolerance applied to exp / nbf checks. ±30 seconds
// matches spec §5h — accommodates modest NTP drift without weakening expiry
// meaning.
const bearerClockSkew = 30 * time.Second

// BearerAuthDeps is a small struct so BuildRouter can construct the middleware
// with clearly-named dependencies.
type BearerAuthDeps struct {
	Pool            *pgxpool.Pool
	UserStore       *store.UserStore
	SigningKeyStore *store.SigningKeyStore
	Valkey          *redis.Client // for revoke_before check (spec §5g)
	Issuer          string        // SCHLASS_PUBLIC_URL with no trailing slash
}

// BearerAuth validates a Bearer JWT against the published signing keys and
// injects the authenticated user + parsed claims into the request context.
// Used by /userinfo.
//
// On any failure, emits 401 with WWW-Authenticate: Bearer error=... per RFC
// 6750 §3.1. Deliberately minimal in observability — /userinfo's best-effort
// oidc.userinfo.accessed audit row is written by the handler, not here, so
// this middleware can stay free of audit-store / tx concerns.
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

			// kid → public PEM resolver from the store. Called once per request
			// and caches nothing (the publishable set is small; DB hit is cheap).
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

			// Policy validation (spec §5h).
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

			// User status check.
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

			// revoke_before: reject access tokens issued before the user
			// mutation cutoff (spec §5g). Fail-open on transport errors —
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

			ctx := context.WithValue(r.Context(), userCtxKey, user)
			ctx = context.WithValue(ctx, bearerClaimsCtxKey{}, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// CurrentBearerClaims returns the parsed access-token claims from the request
// context. Returns (nil, false) if the request did not pass through
// BearerAuth. /userinfo uses this to know which scopes to emit.
func CurrentBearerClaims(ctx context.Context) (*oidc.AccessTokenClaims, bool) {
	c, ok := ctx.Value(bearerClaimsCtxKey{}).(*oidc.AccessTokenClaims)
	return c, ok
}

// extractBearerToken parses an "Authorization: Bearer ..." header. Returns the
// raw token or empty string if absent/malformed. Case-insensitive on the scheme.
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

// writeBearerError responds with an OAuth 2.0 bearer error per RFC 6750 §3.1.
func writeBearerError(w http.ResponseWriter, status int, oauthErr, description string) {
	// Build the WWW-Authenticate challenge. Quote the fields as the spec
	// requires; description may not contain quotes or backslashes.
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error=%q, error_description=%q`, oauthErr, description))
	writeAuthError(w, status, strings.ToUpper(oauthErr), description)
}
