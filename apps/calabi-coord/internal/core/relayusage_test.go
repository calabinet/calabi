package core

import (
	"context"
	"errors"
	"testing"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

type capturingSink struct {
	got  []RelayUsageRecord
	fail error
}

func (s *capturingSink) RecordRelayUsage(_ context.Context, recs []RelayUsageRecord) error {
	if s.fail != nil {
		return s.fail
	}
	s.got = append(s.got, recs...)
	return nil
}

func recordFor(recs []RelayUsageRecord, t MeshnetID) RelayUsageRecord {
	for _, r := range recs {
		if r.Meshnet == t {
			return r
		}
	}
	return RelayUsageRecord{}
}

// The relay hands over opaque keys; this is where they become somebody's bytes.
// Per-meshnet aggregation is the point: two nodes of the same org relaying
// through one region are one line on that org's bill.
func TestRelayUsageIsAttributedPerMeshnet(t *testing.T) {
	c := newTestCoord()
	sink := &capturingSink{}
	c.RelayUsageSink = sink
	ctx := context.Background()

	a, _ := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "a", NodeKey: key(1)})
	b, _ := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "b", NodeKey: key(2)})
	other, _ := c.Register(ctx, RegisterInput{Meshnet: 2, Name: "other", NodeKey: key(3)})
	_, _, _ = a, b, other

	attributed, dropped, err := c.RecordRelayUsage(ctx, "lax", []RelayUsage{
		{Key: key(1), BytesIn: 100, BytesOut: 10},
		{Key: key(2), BytesIn: 200, BytesOut: 20},
		{Key: key(3), BytesIn: 5, BytesOut: 1},
	})
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if attributed != 3 || dropped != 0 {
		t.Fatalf("attributed=%d dropped=%d, want 3/0", attributed, dropped)
	}
	if len(sink.got) != 2 {
		t.Fatalf("got %d records, want one per meshnet", len(sink.got))
	}
	mine := recordFor(sink.got, 1)
	if mine.BytesIn != 300 || mine.BytesOut != 30 {
		t.Errorf("meshnet 1 = %d/%d, want 300/30", mine.BytesIn, mine.BytesOut)
	}
	if mine.Region != "lax" {
		t.Errorf("region = %q, want lax — usage has to say WHICH relay carried it", mine.Region)
	}
	// Both directions survive intact: halving or summing them here would hide a
	// decision that belongs downstream, where it can change without redeploying
	// a fleet of relays.
	theirs := recordFor(sink.got, 2)
	if theirs.BytesIn != 5 || theirs.BytesOut != 1 {
		t.Errorf("meshnet 2 = %d/%d, want 5/1", theirs.BytesIn, theirs.BytesOut)
	}
}

// A key nobody owns is dropped, never guessed at. It means a deleted node, a
// node from another deployment pointed at this relay, or an invention — and in
// all three cases billing someone is worse than losing the bytes.
func TestUnattributableUsageIsDroppedNotGuessed(t *testing.T) {
	c := newTestCoord()
	sink := &capturingSink{}
	c.RelayUsageSink = sink
	ctx := context.Background()
	_, _ = c.Register(ctx, RegisterInput{Meshnet: 1, Name: "a", NodeKey: key(1)})

	attributed, dropped, err := c.RecordRelayUsage(ctx, "lax", []RelayUsage{
		{Key: key(1), BytesIn: 100},
		{Key: key(9), BytesIn: 999999},
	})
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if attributed != 1 || dropped != 1 {
		t.Fatalf("attributed=%d dropped=%d, want 1/1", attributed, dropped)
	}
	if len(sink.got) != 1 {
		t.Fatalf("got %d records, want 1", len(sink.got))
	}
	if sink.got[0].BytesIn != 100 {
		t.Errorf("orphan bytes leaked into a real org's total: %d", sink.got[0].BytesIn)
	}
}

type noResolverStore struct{ NodeStore }

// A coordinator that cannot resolve keys must say so loudly. Silently discarding
// usage would be indistinguishable from "the relays are idle" — the exact shape
// of a billing bug nobody notices for months.
func TestUsageWithoutAResolverIsAnError(t *testing.T) {
	c := newTestCoord()
	c.Nodes = noResolverStore{c.Nodes}
	_, _, err := c.RecordRelayUsage(context.Background(), "lax", []RelayUsage{{Key: key(1), BytesIn: 1}})
	if !errors.Is(err, ErrNoNodeKeyResolver) {
		t.Fatalf("err = %v, want ErrNoNodeKeyResolver", err)
	}
}

func TestEmptyReportDoesNothing(t *testing.T) {
	c := newTestCoord()
	sink := &capturingSink{}
	c.RelayUsageSink = sink
	if _, _, err := c.RecordRelayUsage(context.Background(), "lax", nil); err != nil {
		t.Fatalf("empty report: %v", err)
	}
	if len(sink.got) != 0 {
		t.Error("an idle relay produced a usage record")
	}
}

// The resolver crosses the tenant boundary by design, so it had better be exact:
// a key that belongs to meshnet 2 must never resolve to a node in meshnet 1.
func TestResolveNodeKeyFindsTheRightTenant(t *testing.T) {
	c := newTestCoord()
	ctx := context.Background()
	_, _ = c.Register(ctx, RegisterInput{Meshnet: 1, Name: "mine", NodeKey: key(1)})
	theirs, _ := c.Register(ctx, RegisterInput{Meshnet: 2, Name: "theirs", NodeKey: key(2)})

	r, ok := c.Nodes.(NodeKeyResolver)
	if !ok {
		t.Fatal("MemNodeStore should implement NodeKeyResolver")
	}
	got, err := r.ResolveNodeKey(ctx, key(2))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.ID != theirs.ID || got.Meshnet != 2 {
		t.Fatalf("resolved to node %d of meshnet %d, want %d/2", got.ID, got.Meshnet, theirs.ID)
	}
	if _, err := r.ResolveNodeKey(ctx, meshproto.NodeKey{9, 9}); !errors.Is(err, ErrNodeNotFound) {
		t.Fatalf("unknown key: err = %v, want ErrNodeNotFound", err)
	}
}
