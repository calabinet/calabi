package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// MeshACLRevision is one saved version of a meshnet's ACL document. Editing
// access rules is the single most dangerous action in the console — a wrong doc
// disconnects every node at once — so each save is appended here and the console
// can put a previous version back (MESH.8e-3).
//
// Append-only by design: rows are never updated, so the history is also the
// record of who changed access and when.
type MeshACLRevision struct{ ent.Schema }

// Annotations pins the table name; ent's snake_case would mangle the run of
// capitals in "MeshACLRevision" (cf. MeshACL -> mesh_ac_ls).
func (MeshACLRevision) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "mesh_acl_revisions"}}
}

func (MeshACLRevision) Fields() []ent.Field {
	return []ent.Field{
		field.Int64("meshnet_id").
			Comment("owning meshnet == org id"),
		field.String("policy_json").
			Default("").
			Comment("the ACL document as saved (core.ACLPolicy JSON)"),
		field.String("actor").
			Default("").
			Comment(`who saved it, as the BFF knows them (e.g. "user:42"); empty when unattributed`),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
	}
}

// Indexes: the console lists a meshnet's revisions newest-first.
func (MeshACLRevision) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("meshnet_id", "created_at"),
	}
}
