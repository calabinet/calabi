package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
)

// CoordSetting is a PLATFORM-wide operational value an operator sets from the
// admin console — as opposed to MeshSetting, which is per-meshnet and belongs to
// the org that owns the meshnet.
//
// Key/value rather than one typed column per knob: the alternative needs a
// schema migration for every new switch, and these are operational values whose
// whole point is that they change without a release. Each key has a typed
// accessor in core so the string never leaks past this layer.
type CoordSetting struct{ ent.Schema }

// Annotations pins the table name; ent would otherwise be fine here, but being
// explicit matches mesh_acls / mesh_conn_records and removes the question.
func (CoordSetting) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "coord_settings"}}
}

func (CoordSetting) Fields() []ent.Field {
	return []ent.Field{
		field.String("key").
			Unique().
			NotEmpty().
			Comment("setting name, e.g. conn_record_retention_days"),
		field.String("value").
			Default("").
			Comment("stored as text; the typed accessor in core owns the parsing and the bounds"),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}
