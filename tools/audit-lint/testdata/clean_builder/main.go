// Fixture: emits via the builder API with safe metadata keys.
// audit-lint must exit 0.
package clean_builder

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
	return NewEvent("user.created").WithMetadata(map[string]any{
		"role":   "admin",
		"reason": "manual_provision",
	}).Build()
}
