// Fixture: emits via the builder API with a denylisted "password" key
// in the WithMetadata argument. audit-lint must exit non-zero with a
// clear violation message pointing here.
package dirty_builder

type Event struct {
	EventType string
	Metadata  map[string]any
}

type EventBuilder struct{ e Event }

func NewEvent(t string) *EventBuilder         { return &EventBuilder{e: Event{EventType: t}} }
func (b *EventBuilder) WithMetadata(m map[string]any) *EventBuilder {
	b.e.Metadata = m
	return b
}
func (b *EventBuilder) Build() Event { return b.e }

func emit() Event {
	return NewEvent("login.succeeded").WithMetadata(map[string]any{
		"password": "hunter2", // REQ-AUD-011 denylist hit
		"reason":   "test_fixture",
	}).Build()
}
