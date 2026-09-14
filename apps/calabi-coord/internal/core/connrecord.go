package core

import (
	"context"
	"fmt"
	"strings"
	"time"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// Connection records — who exchanged traffic with whom, when, and how much.
//
// This is the data-plane half of an audit trail. The control-plane half (who
// changed an access rule, who approved a device) already exists in audit-svc's
// hash chain; an auditor asks both questions and we could only answer one.
//
// It revises "current value, never a time series",
// narrowly and on purpose. What protects is spelled out there: a sequence of
// a laptop's ENDPOINT ADDRESSES is a location trail, because a public IP
// reverse-resolves to a place and an ISP. Nothing here carries an endpoint, a
// public IP or a port — a peer pair plus a byte count is an access trail, which
// is a different thing and the one an enterprise buyer is asking for.
//
// Two properties to keep in mind when extending this:
//
//  1. SELF-REPORTED. The reporting node does its own arithmetic on WireGuard's
//     counters. A compromised device can under-report itself, so these are
//     observations and not proof — the console says so, and nothing here should
//     ever become an authorization input.
//  2. HOURLY. Nodes report every few minutes so a crash loses minutes, and the
//     coordinator folds those reports into the hour. Per-report rows would be
//     millions a day for a fleet that mostly talks to a handful of servers.

// ConnSample is one peer over one window, as the reporting node saw it. Deltas,
// never totals: WireGuard's counters are cumulative and reset when a peer is
// reconfigured, so only the node can turn two readings into a number.
type ConnSample struct {
	PeerNodeKey meshproto.NodeKey
	WindowStart time.Time
	WindowEnd   time.Time
	BytesTx     int64
	BytesRx     int64
	Path        string
}

// ConnRecord is one stored hour between one pair.
type ConnRecord struct {
	MeshnetID MeshnetID
	SrcNodeID int64
	DstNodeID int64
	Hour      time.Time
	BytesTx   int64
	BytesRx   int64
	Path      string
}

// ConnRecordStore persists connection records. Separate from NodeStore because a
// deployment may reasonably run the mesh without keeping this history at all —
// a nil store means the feature is off, not broken.
type ConnRecordStore interface {
	// AddConnSamples folds samples into their hourly buckets, adding to whatever
	// is already there.
	AddConnSamples(ctx context.Context, recs []ConnRecord) error
	// ListConnRecords returns rows for a meshnet within [from, to), newest hour
	// first, at most limit rows.
	ListConnRecords(ctx context.Context, t MeshnetID, from, to time.Time, limit int) ([]ConnRecord, error)
	// PurgeConnRecordsBefore deletes rows older than cutoff and returns how many
	// went. Retention is not optional: an access trail nobody trims becomes a
	// liability of its own.
	PurgeConnRecordsBefore(ctx context.Context, cutoff time.Time) (int, error)
	// PurgeConnRecordsOf deletes everything stored for one meshnet. Used when an
	// org turns the trail off: "stop collecting" without "delete what you have"
	// would leave the claim false for a whole retention window.
	PurgeConnRecordsOf(ctx context.Context, t MeshnetID) (int, error)
}

// maxConnSamplesPerReport bounds one call. A node with a few hundred peers over
// a five-minute window is nowhere near this; a node sending more is either
// broken or probing, and either way the answer is to refuse the excess rather
// than to write it.
const maxConnSamplesPerReport = 512

// RecordConnections resolves each sample's peer inside the reporting node's own
// meshnet and folds the result into hourly rows. Returns how many were stored.
//
// Samples whose peer does not resolve are DROPPED, not an error: a node that
// reports a peer removed a second ago is racing, not lying, and failing the
// whole call would lose the good samples with it. A key from another org
// resolves to nothing here — that is the org boundary, and it is why the peer
// lookup is scoped to the reporter's meshnet rather than global.
func (c *Coordinator) RecordConnections(ctx context.Context, srcNodeID int64, samples []ConnSample) (int, error) {
	if c.ConnRecords == nil || len(samples) == 0 {
		return 0, nil
	}
	if len(samples) > maxConnSamplesPerReport {
		samples = samples[:maxConnSamplesPerReport]
	}
	src, err := c.Nodes.Get(ctx, srcNodeID)
	if err != nil {
		return 0, fmt.Errorf("core: connection report: %w", err)
	}
	// The org's own opt-out. Checked HERE, at the one place a row can be born,
	// so there is no second path that could keep writing after the switch.
	//
	// A settings read that fails does NOT fall back to recording: an org that
	// asked us to keep nothing must not start keeping things because a query
	// timed out. The cost of the safe direction is a gap in a trail; the cost of
	// the other one is holding data somebody is contractually forbidden to hold.
	if c.Settings != nil {
		set, serr := c.Settings.GetSettings(ctx, src.Meshnet)
		if serr != nil {
			return 0, fmt.Errorf("core: connection report settings: %w", serr)
		}
		if set.ConnRecordsDisabled {
			return 0, nil
		}
	}
	peers, err := c.Nodes.ListMeshnet(ctx, src.Meshnet)
	if err != nil {
		return 0, fmt.Errorf("core: connection report peers: %w", err)
	}
	byKey := make(map[meshproto.NodeKey]int64, len(peers))
	for _, p := range peers {
		byKey[p.NodeKey] = p.ID
	}

	// Fold in memory first: a five-minute report can hold several samples that
	// land in the same hour for the same peer (a window that straddles the
	// boundary), and one row per pair-hour is the whole point of the bucket.
	type key struct {
		dst  int64
		hour time.Time
	}
	folded := map[key]*ConnRecord{}
	for _, s := range samples {
		dst, ok := byKey[s.PeerNodeKey]
		if !ok || dst == srcNodeID {
			continue
		}
		if s.BytesTx < 0 || s.BytesRx < 0 {
			continue // a counter that went backwards is a reset the node mishandled
		}
		at := s.WindowStart
		if at.IsZero() {
			at = s.WindowEnd
		}
		if at.IsZero() {
			continue
		}
		k := key{dst: dst, hour: at.UTC().Truncate(time.Hour)}
		r := folded[k]
		if r == nil {
			r = &ConnRecord{
				MeshnetID: src.Meshnet,
				SrcNodeID: srcNodeID,
				DstNodeID: dst,
				Hour:      k.hour,
			}
			folded[k] = r
		}
		r.BytesTx += s.BytesTx
		r.BytesRx += s.BytesRx
		if p := normalizeConnPath(s.Path); p != "" {
			r.Path = p
		}
	}
	if len(folded) == 0 {
		return 0, nil
	}
	out := make([]ConnRecord, 0, len(folded))
	for _, r := range folded {
		out = append(out, *r)
	}
	if err := c.ConnRecords.AddConnSamples(ctx, out); err != nil {
		return 0, fmt.Errorf("core: store connection records: %w", err)
	}
	return len(out), nil
}

// normalizeConnPath keeps the two values this field is allowed to hold. Anything
// else is dropped rather than stored: the column exists so a reader can tell a
// direct hop from a relayed one, and a node inventing a third value would make
// that column unreadable for everyone.
func normalizeConnPath(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "direct":
		return "direct"
	case "relay":
		return "relay"
	default:
		return ""
	}
}
