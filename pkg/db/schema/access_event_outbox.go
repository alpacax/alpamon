package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// AccessEventOutbox holds login events the agent has accepted from the PAM
// session hook but not yet delivered to Alpacon, so an outage delays them
// instead of losing them.
type AccessEventOutbox struct {
	ent.Schema
}

func (AccessEventOutbox) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "access_event_outbox"},
	}
}

// Fields of the AccessEventOutbox. Times are written in UTC: the driver stores
// them as text, so one offset is what keeps text order equal to time order.
func (AccessEventOutbox) Fields() []ent.Field {
	return []ent.Field{
		// The event's own id, which the server deduplicates on.
		field.String("id").StorageKey("event_id").NotEmpty().Immutable(),
		// The JSON body as captured, without held_seconds.
		field.Bytes("payload").Immutable(),
		field.Time("created_at").Immutable(),
		field.Int("attempts").Default(0).NonNegative(),
		field.Time("next_attempt_at"),
	}
}

func (AccessEventOutbox) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("created_at"),
		index.Fields("next_attempt_at"),
	}
}
