package core

import (
	"context"
	"errors"
	"fmt"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// Attributing relay usage (F2).
//
// A relay reports opaque node keys and nothing else — it has no concept of an
// org and is never going to acquire one, because that ignorance is what lets the
// same binary run on a user's VPS with nothing to phone home to. Turning those
// keys into orgs is the coordinator's job, and this file is where it happens.
//
// Both directions arrive and both are kept. One relayed packet appears twice —
// as the sender's In and the receiver's Out — and since both ends of a mesh link
// belong to the same meshnet, summing them would bill that org twice. The
// billing formula (egress is the closest match to what the platform actually
// pays for) belongs downstream, where it can change without redeploying relays.

// RelayUsage is one node's relayed byte counts, exactly as a relay reported them.
type RelayUsage struct {
	Key      meshproto.NodeKey `json:"key"`
	BytesIn  uint64            `json:"bytes_in"`
	BytesOut uint64            `json:"bytes_out"`
}

// RelayUsageRecord is usage that has been attributed to a meshnet.
type RelayUsageRecord struct {
	Meshnet  MeshnetID `json:"meshnet"`
	Region   string    `json:"region"`
	BytesIn  uint64    `json:"bytes_in"`
	BytesOut uint64    `json:"bytes_out"`
}

// RelayUsageSink receives attributed usage. Nil on a coordinator that collects
// nothing.
type RelayUsageSink interface {
	RecordRelayUsage(ctx context.Context, recs []RelayUsageRecord) error
}

// NodeKeyResolver looks a node up by key WITHOUT knowing its meshnet.
//
// Deliberately an OPTIONAL capability rather than part of NodeStore: every other
// lookup in this package is scoped to one meshnet, and that scoping is a real
// part of tenant isolation. Relay usage is the one place that genuinely cannot
// be scoped — the relay does not know whose key it is holding — so the ability
// to cross the boundary is opted into by the stores that need it, not handed to
// everything that persists a node.
//
// The result is used to decide WHOSE BYTES THESE ARE. It must never be used to
// grant access.
type NodeKeyResolver interface {
	ResolveNodeKey(ctx context.Context, key meshproto.NodeKey) (*Node, error)
}

// ErrAmbiguousNodeKey is returned when a key matches more than one node. Node
// keys are 32 random bytes, so this does not happen by accident; if it ever
// does, guessing an owner would bill the wrong org, so the caller drops the
// bytes instead.
var ErrAmbiguousNodeKey = errors.New("core: node key matches more than one node")

// ErrNoNodeKeyResolver is returned when relay usage arrives at a coordinator
// whose store cannot resolve keys. Loud on purpose: silently discarding usage
// would look exactly like "the relays are idle".
var ErrNoNodeKeyResolver = errors.New("core: this coordinator cannot attribute relay usage (store has no key resolver)")

// RecordRelayUsage attributes one relay's report and forwards it to the sink,
// aggregated per meshnet. It returns how many entries were attributed and how
// many were dropped.
//
// An unresolvable key is DROPPED, never guessed at and never attributed to
// anyone: it means a deleted node, a node from another deployment pointed at
// this relay, or a fabricated key. All three are cases where billing someone
// would be worse than losing the bytes.
func (c *Coordinator) RecordRelayUsage(ctx context.Context, region string, in []RelayUsage) (attributed, dropped int, err error) {
	if len(in) == 0 {
		return 0, 0, nil
	}
	resolver, ok := c.Nodes.(NodeKeyResolver)
	if !ok {
		return 0, 0, ErrNoNodeKeyResolver
	}
	byMeshnet := map[MeshnetID]*RelayUsageRecord{}
	for _, u := range in {
		node, err := resolver.ResolveNodeKey(ctx, u.Key)
		if err != nil {
			dropped++
			if c.Logger != nil {
				c.Logger.Debug("core: dropping unattributable relay usage",
					"region", region, "key", u.Key, "bytes_in", u.BytesIn, "bytes_out", u.BytesOut, "err", err)
			}
			continue
		}
		rec, seen := byMeshnet[node.Meshnet]
		if !seen {
			rec = &RelayUsageRecord{Meshnet: node.Meshnet, Region: region}
			byMeshnet[node.Meshnet] = rec
		}
		rec.BytesIn += u.BytesIn
		rec.BytesOut += u.BytesOut
		attributed++
	}
	if c.RelayUsageSink == nil || len(byMeshnet) == 0 {
		return attributed, dropped, nil
	}
	recs := make([]RelayUsageRecord, 0, len(byMeshnet))
	for _, rec := range byMeshnet {
		recs = append(recs, *rec)
	}
	if err := c.RelayUsageSink.RecordRelayUsage(ctx, recs); err != nil {
		return attributed, dropped, fmt.Errorf("core: record relay usage: %w", err)
	}
	return attributed, dropped, nil
}
