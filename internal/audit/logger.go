package audit

import (
	"context"

	"github.com/google/uuid"

	"github.com/abdo75/Schlass/internal/database"
)

// Logger is the narrow write interface consumed by handlers, middleware, and
// the scheduler. *Store satisfies it; integration tests may inject a fake.
type Logger interface {
	Log(ctx context.Context, q database.Querier, entry Entry) error
}

// PseudonymizingLogger extends Logger with the GDPR Art. 17 mutation path.
// Used by auth and users handlers that need to both log and pseudonymize.
// *Store satisfies this interface; integration tests inject a fake.
type PseudonymizingLogger interface {
	Logger
	PseudonymizeUser(ctx context.Context, q database.Querier, userID uuid.UUID) (int, error)
}
