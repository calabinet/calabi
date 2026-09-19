package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// MeshConnRecord is one hour of traffic between one pair of devices, as the
// SOURCE device reported it — the data-plane half of an audit trail. The
// control-plane half (who changed a rule, who approved a device) is already in
// audit-svc's hash chain; this answers the other question an auditor asks, which
// is who actually connected to what.
//
// It revises "current value, never a time series",
// and only that far: what that rule protects is a sequence of ENDPOINT
// ADDRESSES, which is a location trail because a public IP resolves to a place.
// There is no endpoint, no public IP and no port in this row — a peer pair plus
// a byte count is an access trail, not a location one.
//
// SELF-REPORTED. A compromised device can under-report itself, so these rows are
// evidence, not proof. The console has to say so.
type MeshConnRecord struct{ ent.Schema }

// Annotations pins the table name; ent's snake_case would otherwise mangle the
// run of capitals in "MeshConnRecord".
func (MeshConnRecord) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "mesh_conn_records"}}
}

func (MeshConnRecord) Fields() []ent.Field {
	return []ent.Field{
		field.Int64("meshnet_id").
			Comment("owning meshnet == org id; every read is scoped to it"),
		field.Int64("src_node_id").
			Comment("the device that REPORTED this row (and sent the bytes_tx)"),
		field.Int64("dst_node_id").
			Comment("the peer it exchanged traffic with, resolved from the reported node key WITHIN the same meshnet — a key from another org resolves to nothing and the sample is dropped"),
		// Hourly bucket, not the raw 5-minute report. A node reports often so a
		// crash loses minutes rather than an hour, and the coordinator folds the
		// reports into the hour — which is the granularity an auditor actually
		// asks in ("who reached the payroll box on the 3rd") and the difference
		// between a few hundred rows an hour and a few million a day.
		field.Time("hour").
			Comment("UTC hour this traffic fell in, truncated; the bucket key"),
		field.Int64("bytes_tx").
			Default(0).
			Comment("bytes src sent to dst during the hour, summed from the node's reports"),
		field.Int64("bytes_rx").
			Default(0).
			Comment("bytes src received from dst during the hour"),
		field.String("path").
			Default("").
			Comment(`"direct" or "relay" as last reported in the hour. NOT an endpoint address — see the type comment`),
		// The relayed part of the two totals above. `path` is only the hour's
		// last reported value, so a pair that moved between relay and direct
		// mid-hour cannot be split by it; a self-hosted server's relay usage is
		// summed from these.
		field.Int64("relay_bytes_tx").
			Default(0).
			Comment("of bytes_tx, what went through a relay"),
		field.Int64("relay_bytes_rx").
			Default(0).
			Comment("of bytes_rx, what came through a relay"),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}

// Indexes. The unique one is what makes a report an upsert-add rather than a new
// row every five minutes; the read index serves the console's only query shape
// ("this org, this time range, newest first").
func (MeshConnRecord) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("meshnet_id", "src_node_id", "dst_node_id", "hour").Unique(),
		index.Fields("meshnet_id", "hour"),
	}
}
