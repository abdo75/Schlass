package audit

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/abdo75/Schlass/internal/database"
)

// Logger is the narrow write interface consumed by handlers, middleware,
// and the scheduler. *Store satisfies it; integration tests inject a fake.
// pgx.Tx is required at the type level (REQ-AUD-062): pool/non-tx
// callers cannot satisfy this signature, so an audit row is always
// committed atomically with the originating mutation.
type Logger interface {
	Emit(ctx context.Context, tx pgx.Tx, event Event) error
}

// PseudonymizingLogger extends Logger with the GDPR Art. 17 mutation
// path. *Store satisfies this; integration tests inject a fake. The
// pseudonymize call accepts database.Querier (not pgx.Tx) so it composes
// with the user-delete tx already in scope at the only call site.
type PseudonymizingLogger interface {
	Logger
	PseudonymizeUser(ctx context.Context, q database.Querier, userID uuid.UUID) (int, error)
}
