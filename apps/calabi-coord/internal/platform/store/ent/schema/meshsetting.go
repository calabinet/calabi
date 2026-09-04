package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

// MeshSetting holds one meshnet's org-level switches (MESH.8e-5). One row per
// meshnet, created on first write — an absent row means "all defaults", which is
// what every meshnet runs on until an admin changes something.
type MeshSetting struct{ ent.Schema }

func (MeshSetting) Fields() []ent.Field {
	return []ent.Field{
		field.Int64("meshnet_id").
			Unique().
			Comment("owning meshnet == org id"),
		field.Bool("require_device_approval").
			Default(false).
			Comment("new devices must be approved by an admin before they can reach anything"),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}
