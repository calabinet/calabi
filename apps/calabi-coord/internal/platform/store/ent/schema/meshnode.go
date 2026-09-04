// Package schema is the ent source-of-truth for calabi-coord's platform tables.
package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// MeshNode is one device enrolled in a meshnet — the persistent backing for
// core.Node (MESH.8c). calabi-coord owns this table (chosen over extending the
// Publish Device registry): the mesh data plane stays self-contained and the
// community coordinator can ship its own persistence later. Slice/key fields are
// stored as text/JSON so a row is portable across sqlite (dev/test) and
// postgres (prod).
type MeshNode struct{ ent.Schema }

// Fields mirror core.Node. node_key is the WireGuard public key (base64 text);
// overlay/disco_key are text; endpoints / advertised routes / tags are JSON
// arrays of strings.
func (MeshNode) Fields() []ent.Field {
	return []ent.Field{
		field.Int64("meshnet_id").
			Comment("owning meshnet == org id (one org = one meshnet)"),
		field.String("node_key").
			NotEmpty().
			Comment("WireGuard public key, base64 text (meshproto.NodeKey.String())"),
		field.String("name").
			Default("").
			Comment("MagicDNS label peers resolve; admin-settable (see core.RenameNode)"),
		field.String("host_name").
			Default("").
			Comment("the name the node reports at registration (its hostname); informational"),
		field.Bool("name_pinned").
			Default(false).
			Comment("name was set by an admin: re-registration stops following the hostname"),
		field.String("disco_key").
			Default("").
			Comment("hole-punch disco key, base64 text; empty until MESH.4"),
		field.String("overlay").
			Default("").
			Comment("allocated 100.64.x.x /32, text"),
		field.String("derp_home").
			Default("").
			Comment("region code of the node's home relay"),
		field.String("endpoints_json").
			Default("[]").
			Comment("JSON array of discovered ip:port endpoints"),
		field.String("advertised_routes_json").
			Default("[]").
			Comment("JSON array of subnet-router / exit CIDRs the node CLAIMS (MESH.7)"),
		field.String("approved_routes_json").
			Default("[]").
			Comment("the subset an admin approved; only these are routed to the node"),
		field.Bool("routes_reviewed").
			Default(false).
			Comment("an admin has managed this node's routes; until then claims are honoured (grandfathering)"),
		field.Int64("owner_user_id").
			Default(0).
			Comment("the human whose key enrolled this node (0 = unattributed)"),
		field.String("device_fingerprint").
			Default("").
			Comment("daemon's self-reported per-install id; lets the console link this device to its client record. Display only — never authorize on it"),
		field.Bool("tags_pinned").
			Default(false).
			Comment("an admin set the tags in the console; re-registration must not overwrite them from the auth key"),
		field.String("tags_json").
			Default("[]").
			Comment("JSON array of ACL tags resolved from the auth key"),
		field.Bool("approved").
			Default(true).
			Comment("device approval (MESH.8e-5): false = enrolled but not yet allowed to reach anything. Defaults TRUE so enabling approval never retroactively parks existing nodes"),
		field.Bool("disabled").
			Default(false).
			Comment("admin kill switch (MESH.8b): dropped from netmaps + refused on re-register"),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
		field.Time("last_seen").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}

// Indexes: FindByKey looks up (meshnet, node_key); a node key is unique within a
// meshnet. ListMeshnet scans by meshnet_id.
func (MeshNode) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("meshnet_id", "node_key").Unique(),
		index.Fields("meshnet_id"),
	}
}
