// Fixture: emits with safe metadata keys. audit-lint must exit 0.
package clean

type Event struct {
	EventType string
	Metadata  map[string]any
}

func emit() Event {
	return Event{
		EventType: "user.created",
		Metadata: map[string]any{
			"role":   "admin",
			"reason": "manual_provision",
		},
	}
}
