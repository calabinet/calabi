package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// MeshTunnel is one reverse tunnel a self-hosted daemon reported serving
// (core/tunnels.go): the node's CURRENT list, replaced by each report. Shown to
// the meshnet's phones; never an authorization input. A platform coordinator
// never writes this table — its tunnels live in tunnel-svc.
type MeshTunnel struct{ ent.Schema }

// Annotations pins the table name, as the other mesh tables do.
func (MeshTunnel) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "mesh_tunnels"}}
}

func (MeshTunnel) Fields() []ent.Field {
	return []ent.Field{
		field.Int64("meshnet_id"),
		field.Int64("node_id").
			Comment("the device whose daemon serves it"),
		field.String("name").
			Comment("the name in the daemon's config; unique on the node"),
		field.String("type").
			Comment("http, https, tcp, udp or sni"),
		field.String("public_addr").
			Default("").
			Comment("where visitors reach it: a host name, or host:port"),
		field.String("local_addr").
			Default(""),
		field.String("status").
			Default("offline").
			Comment("online, pending or offline, as last reported"),
		field.Time("first_seen").
			Comment("when the node first reported a tunnel by this name"),
		field.Time("reported_at").
			Comment("when the node last reported"),
	}
}

func (MeshTunnel) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("node_id", "name").Unique(),
		index.Fields("meshnet_id"),
	}
}

// MeshTunnelUsage is one tunnel's traffic in one UTC hour, summed from its
// daemon's reports (core/tunnels.go). Kept core.TunnelUsageRetention and swept
// daily with the connection records. Rows outlive the node they came from: the
// traffic still happened in the month it happened in.
type MeshTunnelUsage struct{ ent.Schema }

func (MeshTunnelUsage) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "mesh_tunnel_usage"}}
}

func (MeshTunnelUsage) Fields() []ent.Field {
	return []ent.Field{
		field.Int64("meshnet_id"),
		field.Int64("node_id"),
		field.String("name").
			Comment("the tunnel's name on the node"),
		field.Time("hour").
			Comment("UTC hour, truncated"),
		field.Int64("bytes_in").
			Default(0).
			Comment("visitors to the local service"),
		field.Int64("bytes_out").
			Default(0).
			Comment("the local service back to visitors"),
	}
}

func (MeshTunnelUsage) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("node_id", "name", "hour").Unique(),
		index.Fields("meshnet_id", "hour"),
	}
}
