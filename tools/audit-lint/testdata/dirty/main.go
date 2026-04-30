// Fixture: emits with a denylisted "password" key. audit-lint must
// exit non-zero with a clear violation message pointing here.
package dirty

type Event struct {
	EventType string
	Metadata  map[string]any
}

func emit() Event {
	return Event{
		EventType: "login.succeeded",
		Metadata: map[string]any{
			"password": "hunter2", // REQ-AUD-011 denylist hit
			"reason":   "test_fixture",
		},
	}
}
