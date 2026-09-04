package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// MeshService is one service offered on a node: "this machine serves postgres on
// 5432". Never DISCOVERED by scanning the node —
// rule it distilled: declaration over discovery.
//
// It arrives one of two ways, which is what `source` records:
//
//   - "node": the machine's own config declares it. A CLAIM, stored pending
//     until an admin confirms it.
//   - "console": an admin entered it here. Creating it IS the authorization, so
//     it starts confirmed, and a node's declaration can never modify or shadow
//     it — authority over the row belongs to whoever has the greater authority
//     over the fact.
//
// The older comment on this type said the console was the only author. That was
// true when a service name decided WHICH MACHINES a rule covered; demoted
// "svc:" to naming ports on the declaring device only, which is what made a
// node's own declaration safe to accept.
type MeshService struct{ ent.Schema }

func (MeshService) Fields() []ent.Field {
	return []ent.Field{
		field.Int64("meshnet_id").
			Comment("owning meshnet == org id"),
		field.Int64("node_id").
			Comment("the node offering it"),
		field.String("name").
			Comment("service label; an ACL selector, unique per node but shared across nodes on purpose (one service, many instances)"),
		field.String("proto").
			Default("tcp").
			Comment("tcp | udp"),
		field.Int("port"),
		field.String("target").
			Default("").
			Comment("what the DEVICE dials to reach the app (host:port); empty = 127.0.0.1:<port>. Distinct from port, which is what mesh peers dial on the overlay address — an app bound to loopback answers the first and not the second"),
		field.String("note").
			Default("").
			Comment("free-text note for humans"),
		field.String("source").
			Default("node").
			Comment("node = the machine's config declares it (a claim); console = an admin entered it (an authorization). Defaults to node so every pre-existing row keeps being reconciled against its device"),
		field.Bool("approved").
			Default(true).
			Comment("gates ACL visibility: a node's claim matches no svc: rule until an admin confirms it. Defaults TRUE so services that predate this never silently stop matching"),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
	}
}

// Indexes: listing is per meshnet; (node, name) is unique — a node has one
// "web", while several nodes may each have one.
func (MeshService) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("meshnet_id"),
		index.Fields("node_id", "name").Unique(),
	}
}
