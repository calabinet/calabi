package store

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
	"github.com/calabinet/calabi/apps/calabi-coord/internal/platform/store/ent/meshnode"
)

// Hiding the optional projection exercises the original full-read algorithm.
type fullRegistrationStore struct{ core.NodeStore }

func TestRegistrationProjectionMatchesFullValidation(t *testing.T) {
	ctx := context.Background()
	newIsolated := func() *Store {
		s, err := Open("sqlite:" + filepath.Join(t.TempDir(), "registration.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close() })
		if err := s.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		return s
	}
	full, compact := newIsolated(), newIsolated()
	route := netip.MustParsePrefix("192.168.9.0/24")
	alias := netip.MustParsePrefix("100.96.0.0/24")
	for _, s := range []*Store{full, compact} {
		for _, n := range []*core.Node{
			{Meshnet: 1, Name: "privileged", NodeKey: key(1), OwnerUserID: 10, ApprovedRoutes: []netip.Prefix{route}, RealRoutes: []netip.Prefix{netip.MustParsePrefix("192.168.9.1/32")}, RouteAliases: []core.RouteAlias{{Real: route, Alias: alias}}},
			{Meshnet: 2, Name: "foreign", NodeKey: key(2)},
		} {
			if _, err := s.Upsert(ctx, n); err != nil {
				t.Fatal(err)
			}
		}
	}
	peers, err := compact.ListRegistrationPeers(ctx, 1)
	if err != nil || len(peers) != 1 {
		t.Fatalf("projection tenant scope: %v %v", peers, err)
	}
	if peers[0].Name != "privileged" || peers[0].OwnerUserID != 10 || !reflect.DeepEqual(core.PublishedRoutes(peers[0]), []netip.Prefix{alias, netip.MustParsePrefix("192.168.9.1/32")}) {
		t.Fatalf("projection lost validation fields: %+v", peers[0])
	}
	a := &core.Coordinator{Nodes: fullRegistrationStore{full}, IPAM: core.NewMemIPAM(), AutoApproveAllRoutes: true}
	b := &core.Coordinator{Nodes: compact, IPAM: core.NewMemIPAM(), AutoApproveAllRoutes: true}
	for _, p := range []core.RegisterInput{
		{Meshnet: 1, Name: "PRIVILEGED", NodeKey: key(3), AdvertisedRoutes: []netip.Prefix{route, alias}},
		{Meshnet: 1, Name: "PRIVILEGED", NodeKey: key(3), AdvertisedRoutes: []netip.Prefix{route, alias}},
		{Meshnet: 1, Name: "foreign", NodeKey: key(4)},
	} {
		x, xc, xe := a.RegisterWithChange(ctx, p)
		y, yc, ye := b.RegisterWithChange(ctx, p)
		if xe != nil || ye != nil {
			t.Fatalf("registration: %v %v", xe, ye)
		}
		if x.Name != y.Name || !reflect.DeepEqual(x.ApprovedRoutes, y.ApprovedRoutes) || xc != yc {
			t.Fatalf("different decision: %+v vs %+v", x, y)
		}
		if p.NodeKey == key(3) && (y.Name == "PRIVILEGED" || len(y.ApprovedRoutes) != 0) {
			t.Fatal("name or route takeover allowed")
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := compact.ListRegistrationPeers(canceled, 1); err == nil {
		t.Fatal("canceled read succeeded")
	}
}

func TestRegistrationProjectionConcurrentQuotaAndFailure(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	c := &core.Coordinator{Nodes: s, IPAM: core.NewMemIPAM(), Quota: core.StaticNodeQuota{Limit: 2}}
	var wg sync.WaitGroup
	for i := byte(1); i <= 8; i++ {
		wg.Add(1)
		go func(i byte) {
			defer wg.Done()
			_, err := c.Register(ctx, core.RegisterInput{Meshnet: 1, Name: "same", NodeKey: key(i)})
			if err != nil && !errors.Is(err, core.ErrNodeQuotaExceeded) {
				t.Errorf("register: %v", err)
			}
		}(i)
	}
	wg.Wait()
	nodes, err := s.ListMeshnet(ctx, 1)
	if err != nil || len(nodes) != 2 || nodes[0].Name == nodes[1].Name {
		t.Fatalf("seat/name race: %+v %v", nodes, err)
	}
	if err := s.SetDisabled(ctx, nodes[0].ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Register(ctx, core.RegisterInput{Meshnet: 1, Name: "same", NodeKey: key(9)}); err != nil {
		t.Fatalf("disabled seat not released: %v", err)
	}
	// A failed projection must not be mistaken for an empty organization.
	if _, err := s.client.MeshNode.Update().Where(meshnode.ID(int(nodes[1].ID))).SetApprovedRoutesJSON("invalid").Save(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Register(ctx, core.RegisterInput{Meshnet: 1, Name: "same", NodeKey: key(10)}); err == nil {
		t.Fatal("corrupt validation data admitted node")
	}
}
