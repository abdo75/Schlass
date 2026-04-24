package users

import (
	"context"
)

type userKey struct{}

// WithCurrentUser stores the authenticated user in ctx. Called by session auth
// and bearer auth middleware so that CurrentUser works identically for both.
func WithCurrentUser(ctx context.Context, u *User) context.Context {
	return context.WithValue(ctx, userKey{}, u)
}

// CurrentUser retrieves the authenticated user injected by auth middleware.
// Returns (nil, false) when the request is unauthenticated.
func CurrentUser(ctx context.Context) (*User, bool) {
	u, ok := ctx.Value(userKey{}).(*User)
	return u, ok
}
