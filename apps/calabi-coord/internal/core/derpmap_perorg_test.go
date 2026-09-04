package core

import (
	"context"
	"errors"
	"testing"
)

// perOrgDERP serves a different directory to each meshnet — what the real source
// does once orgs can register relays of their own (R2). Until then StaticDERP
// ignores the meshnet and every org sees the same map, which is why the existing
// test suite is unchanged by R1.
type perOrgDERP map[MeshnetID]DERPMap

func (p perOrgDERP) DERPMap(_ context.Context, t MeshnetID) (DERPMap, error) {
	return p[t], nil
}

func region(code string) DERPRegion {
	return DERPRegion{Code: code, Nodes: []DERPNode{{HostName: code + ".example", DERPPort: 3340, STUNPort: 3478}}}
}

func TestNetMapCarriesTheMeshnetsOwnDERPMap(t *testing.T) {
	c := newTestCoord()
	c.DERP = perOrgDERP{
		1: {Regions: []DERPRegion{region("lax"), region("self-acme-tokyo")}},
		2: {Regions: []DERPRegion{region("lax")}},
	}
	ctx := context.Background()

	mine, _ := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "mine", NodeKey: key(1)})
	theirs, _ := c.Register(ctx, RegisterInput{Meshnet: 2, Name: "theirs", NodeKey: key(2)})

	nm, err := c.NetMapFor(ctx, mine.ID)
	if err != nil {
		t.Fatalf("netmap: %v", err)
	}
	if !nm.DERP.HasRegion("self-acme-tokyo") {
		t.Error("the meshnet's own relay is missing from its map")
	}

	other, err := c.NetMapFor(ctx, theirs.ID)
	if err != nil {
		t.Fatalf("netmap: %v", err)
	}
	// The whole reason the map is per-org: a relay sees no plaintext but it does
	// see who talks to whom, how much and when. Another org's relay in your map
	// hands that picture to its operator.
	if other.DERP.HasRegion("self-acme-tokyo") {
		t.Error("one meshnet's self-hosted relay leaked into another's map")
	}
}

// derp_home is redistributed to peers as "relay here to reach this node", so a
// node that could name a region outside its own map would send its peers at a
// relay that isn't theirs — or park a foreign label in their consoles.
func TestSetDERPHomeIsScopedToTheNodesOwnMeshnet(t *testing.T) {
	c := newTestCoord()
	c.DERP = perOrgDERP{
		1: {Regions: []DERPRegion{region("lax")}},
		2: {Regions: []DERPRegion{region("lax"), region("self-acme-tokyo")}},
	}
	ctx := context.Background()
	n, _ := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "mine", NodeKey: key(1)})

	if _, err := c.SetDERPHome(ctx, n.ID, "self-acme-tokyo"); !errors.Is(err, ErrUnknownDERPRegion) {
		t.Fatalf("node claimed a region from another meshnet's map (err=%v)", err)
	}
	if _, err := c.SetDERPHome(ctx, n.ID, "lax"); err != nil {
		t.Fatalf("node could not claim a region from its own map: %v", err)
	}
}
