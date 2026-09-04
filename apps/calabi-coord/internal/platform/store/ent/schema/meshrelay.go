package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// MeshRelay is a calabi-derp an ORG runs itself (R2).
//
// A declaration, not a discovery: the user tells the console an address and the
// relay itself is not touched. calabi-derp has no idea a coordinator exists and
// is never going to learn — that ignorance is what makes the same binary safe to
// hand out, so registration cannot involve it.
//
// The row lives per meshnet because an org's relay must appear ONLY in that
// org's map. A relay sees no plaintext, but it does see the metadata: who talks
// to whom, how much, when. See core/relay.go for the three constraints.
type MeshRelay struct{ ent.Schema }

// Annotations pins the table name rather than trusting the pluralizer — a
// surprise here is a silent second table, and the fix is a DROP.
func (MeshRelay) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "mesh_relays"}}
}

func (MeshRelay) Fields() []ent.Field {
	return []ent.Field{
		field.Int64("meshnet_id").
			Comment("owning meshnet == org id"),
		field.String("label").
			Comment("DNS label chosen by the user; the region code is \"self-\"+label, derived not stored, so the two cannot drift"),
		field.String("host_name").
			Comment("public address MESH NODES dial — must be reachable from wherever this org's devices are"),
		field.Int("derp_port").
			Default(3340),
		field.Int("stun_port").
			Default(3478).
			Comment("a region with no STUN endpoint cannot be latency-measured, so it is never chosen as anyone's home"),
		field.Bool("enabled").
			Default(true).
			Comment("false parks the relay: the row stays, the region leaves the map"),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
	}
}

// Indexes: listing is per meshnet; (meshnet, label) is unique because the label
// becomes a region code and two regions with one code is not a thing.
func (MeshRelay) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("meshnet_id"),
		index.Fields("meshnet_id", "label").Unique(),
	}
}
