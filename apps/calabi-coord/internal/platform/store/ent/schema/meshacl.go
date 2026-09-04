package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
)

// MeshACL is one meshnet's access-control document — the persistent backing for
// the console ACL editor (MESH.8e-2). calabi-coord owns this table (same call as
// mesh_nodes in 8c: the mesh data plane stays self-contained). One row per
// meshnet; the document is stored as JSON text so it is portable across sqlite
// (dev/test) and postgres (prod) and forward-compatible if the ACL model grows.
type MeshACL struct{ ent.Schema }

// Annotations pins the table name to "mesh_acls". Without this, ent derives it
// from the type name "MeshACL" as "mesh_ac_ls" (the run of capitals confuses its
// snake_case) — an ugly name. The explicit override keeps the table readable.
func (MeshACL) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "mesh_acls"}}
}

// Fields: meshnet_id is the org id (one ACL doc per meshnet), unique so a write
// is an upsert-by-meshnet. policy_json is the marshalled core.ACLPolicy.
func (MeshACL) Fields() []ent.Field {
	return []ent.Field{
		field.Int64("meshnet_id").
			Unique().
			Comment("owning meshnet == org id; one ACL doc per meshnet"),
		field.String("policy_json").
			Default("").
			Comment("the ACL document as JSON (core.ACLPolicy)"),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}
