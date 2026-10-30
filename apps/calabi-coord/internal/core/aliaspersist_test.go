package core

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

type aliasWriteFault struct {
	NodeStore
	fail bool
}

func (s *aliasWriteFault) UpdateRouteAliases(ctx context.Context, id int64, aliases []RouteAlias) error {
	if s.fail {
		return errors.New("injected alias save failure")
	}
	return s.NodeStore.UpdateRouteAliases(ctx, id, aliases)
}

type observedAliasRelease struct {
	AliasIPAM
	nodes  NodeStore
	nodeID int64
	t      *testing.T
	calls  int
}

func (p *observedAliasRelease) Release(ctx context.Context, alias netip.Prefix) error {
	n, err := p.nodes.Get(ctx, p.nodeID)
	if err != nil {
		return err
	}
	if len(n.RouteAliases) != 0 {
		p.t.Error("alias reservation released before persisted mapping was removed")
	}
	p.calls++
	return p.AliasIPAM.Release(ctx, alias)
}

func TestRouteAliasReservationIsReleasedOnlyAfterPersistence(t *testing.T) {
	ctx := context.Background()
	st := NewMemNodeStore()
	real := netip.MustParsePrefix("192.168.99.0/24")
	alias := netip.MustParsePrefix("100.96.99.0/24")
	n, err := st.Upsert(ctx, &Node{Meshnet: 1, Approved: true, AdvertisedRoutes: []netip.Prefix{real}, ApprovedRoutes: []netip.Prefix{real}, AliasedRoutes: []netip.Prefix{real}, RouteAliases: []RouteAlias{{Real: real, Alias: alias}}})
	if err != nil {
		t.Fatal(err)
	}
	fault := &aliasWriteFault{NodeStore: st, fail: true}
	pool := &observedAliasRelease{AliasIPAM: NewMemAliasIPAM(), nodes: st, nodeID: n.ID, t: t}
	c := &Coordinator{Nodes: fault, AliasIPAM: pool}
	if _, err = c.ApproveRoutes(ctx, 1, n.ID, nil); err == nil {
		t.Fatal("expected partial persistence failure")
	}
	if pool.calls != 0 {
		t.Fatal("failed persistence freed an address still referenced in storage")
	}
	fault.fail = false
	if _, err = c.ApproveRoutes(ctx, 1, n.ID, nil); err != nil {
		t.Fatal(err)
	}
	if pool.calls != 1 {
		t.Fatalf("successful retry release count=%d", pool.calls)
	}
	if _, err = c.ApproveRoutes(ctx, 1, n.ID, nil); err != nil {
		t.Fatal(err)
	}
	if pool.calls != 1 {
		t.Fatal("idempotent retry freed reservation twice")
	}
}
