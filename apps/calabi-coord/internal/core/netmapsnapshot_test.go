package core

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"sort"
	"testing"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

func snapshotFixture(t *testing.T) (*Coordinator, *MemNodeStore, []*Node) {
	t.Helper()
	st := NewMemNodeStore()
	var nodes []*Node
	for i := 1; i <= 3; i++ {
		n, err := st.Upsert(context.Background(), &Node{Meshnet: 1, Name: []string{"", "alice", "bob", "carol"}[i], NodeKey: meshproto.NodeKey{byte(i)}, Approved: true, Tags: []string{"tag:test"}, Overlay: netip.AddrFrom4([4]byte{100, 64, 0, byte(i)}), Endpoints: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.10:1234")}})
		if err != nil {
			t.Fatal(err)
		}
		nodes = append(nodes, n)
	}
	c := &Coordinator{Nodes: st, Policy: AllowAllPolicy{}, DERP: StaticDERP{Map: DERPMap{Regions: []DERPRegion{{Code: "test"}}}}}
	return c, st, nodes
}

func TestNetMapSnapshotMatchesFreshMapsAndFreezesPolicy(t *testing.T) {
	c, _, nodes := snapshotFixture(t)
	acl := NewMemACLStore()
	doc := ACLPolicy{ACLs: []ACLRule{{Action: "accept", Src: []string{"alice"}, Dst: []string{"bob"}, Ports: []string{"443"}}}}
	if err := acl.SetACL(context.Background(), 1, doc); err != nil {
		t.Fatal(err)
	}
	c.ACL, c.Policy = acl, ACLFilter{Store: acl, Fallback: AllowAllPolicy{}}
	s, err := c.PrepareNetMapSnapshot(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		fresh, err := c.NetMapFor(context.Background(), n.ID)
		if err != nil {
			t.Fatal(err)
		}
		got, err := s.NetMapFor(context.Background(), n.ID)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range []*NetMap{fresh, got} {
			sort.Slice(m.Peers, func(i, j int) bool { return m.Peers[i].ID < m.Peers[j].ID })
		}
		if !reflect.DeepEqual(fresh, got) {
			t.Fatalf("snapshot changed node %d map: fresh=%+v shared=%+v", n.ID, fresh, got)
		}
		view, peers, err := s.NetMapViewFor(context.Background(), n.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(view.Peers) != 0 {
			t.Fatal("read-only path copied Node values")
		}
		for _, p := range peers {
			view.Peers = append(view.Peers, cloneMapNode(*p))
		}
		sort.Slice(view.Peers, func(i, j int) bool { return view.Peers[i].ID < view.Peers[j].ID })
		if !reflect.DeepEqual(fresh, view) {
			t.Fatalf("read-only ACL/filter view differs for %d", n.ID)
		}
	}
	before, _ := s.NetMapFor(context.Background(), nodes[1].ID)
	// Simulate a reload mutating the input document; an existing snapshot stays
	// immutable until the dispatcher discards its generation.
	doc.ACLs[0].Ports[0] = "22"
	after, _ := s.NetMapFor(context.Background(), nodes[1].ID)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("shared document mutated")
	}
}

func TestNetMapSnapshotIsolatesOutputAndChecksDeviceState(t *testing.T) {
	c, st, nodes := snapshotFixture(t)
	st.SetDisabled(context.Background(), nodes[2].ID, true)
	st.SetApproved(context.Background(), nodes[1].ID, false)
	s, err := c.PrepareNetMapSnapshot(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.NetMapFor(context.Background(), nodes[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Peers) != 0 {
		t.Fatal("unapproved or disabled device leaked")
	}
	view, peers, err := s.NetMapViewFor(context.Background(), nodes[0].ID)
	if err != nil || len(peers) != 0 || len(view.Peers) != 0 {
		t.Fatal("read-only view leaked disabled/pending peer")
	}
	if _, _, err := s.NetMapViewFor(context.Background(), nodes[2].ID); !errors.Is(err, ErrNodeDisabled) {
		t.Fatal("read-only view admitted disabled device")
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if _, peers, err := s.NetMapViewFor(cancelled, nodes[0].ID); !errors.Is(err, context.Canceled) || len(peers) != 0 {
		t.Fatal("cancelled view published peers")
	}
	a.Self.Tags[0] = "tag:changed"
	a.Self.Endpoints[0] = netip.MustParseAddrPort("203.0.113.99:12")
	a.DERP.Regions[0].Code = "changed"
	b, _ := s.NetMapFor(context.Background(), nodes[0].ID)
	if b.Self.Tags[0] != "tag:test" || b.Self.Endpoints[0] != nodes[0].Endpoints[0] || b.DERP.Regions[0].Code != "test" {
		t.Fatal("map output mutated shared inputs")
	}
	if _, err := s.NetMapFor(context.Background(), nodes[2].ID); !errors.Is(err, ErrNodeDisabled) {
		t.Fatal(err)
	}
	if _, err := s.NetMapFor(context.Background(), 9999); !errors.Is(err, ErrNodeNotFound) {
		t.Fatal(err)
	}
	pending, err := s.NetMapFor(context.Background(), nodes[1].ID)
	if err != nil || len(pending.Peers) != 0 || len(pending.PacketFilter) != 0 {
		t.Fatal("pending device gained access", err)
	}
}
