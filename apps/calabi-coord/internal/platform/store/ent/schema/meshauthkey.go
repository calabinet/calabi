package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// MeshAuthKey is an auth key a self-hosted coordinator minted itself — an
// invite (core/authkeys.go). The key is never stored, only its SHA-256: it is
// shown once, when it is created. A platform coordinator (identity-svc behind
// it) never writes this table.
type MeshAuthKey struct{ ent.Schema }

// Annotations pins the table name, as the other mesh tables do.
func (MeshAuthKey) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "mesh_auth_keys"}}
}

func (MeshAuthKey) Fields() []ent.Field {
	return []ent.Field{
		field.Int64("meshnet_id").
			Comment("the meshnet a device this key admits joins"),
		field.String("hash").
			NotEmpty().
			Comment("hex SHA-256 of the key; the key itself is never stored"),
		field.String("prefix").
			Default("").
			Comment("the key's first characters, to recognise it in a list"),
		field.String("tags_json").
			Default("[]").
			Comment("JSON array of ACL tags stamped on every device it admits"),
		field.Int("max_uses").
			Default(0).
			Comment("how many devices it may admit; 0 = any number"),
		field.Int("uses").
			Default(0).
			Comment("how many devices it has admitted"),
		field.Time("expires_at").
			Optional().
			Nillable().
			Comment("after this it admits no new device; NULL = never"),
		field.Time("revoked_at").
			Optional().
			Nillable().
			Comment("revoked: refused outright; NULL = not revoked"),
		field.String("note").
			Default("").
			Comment("the operator's own label"),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
	}
}

func (MeshAuthKey) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("hash").Unique(),
		index.Fields("meshnet_id"),
	}
}
