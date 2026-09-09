package rpc

import (
	"net/netip"
	"testing"

	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
)

// A node's own registered services must ride its netmap, because that is the
// only way it learns about ones a manager entered in the console — the machine's
// config has never heard of those, so without this they could never be
// self-checked and showed "not observed" forever.
//
// NetMapFor has always put them on Self (it swaps in the enriched copy so an
// "svc:" rule about self matches like it does for peers); they just never
// crossed the wire.
func TestNetMapCarriesTheNodesOwnServices(t *testing.T) {
	nm := &core.NetMap{
		Self: core.Node{
			ID:      7,
			Overlay: netip.MustParseAddr("100.64.0.7"),
			Services: []core.Service{
				{Name: "db", Proto: "tcp", Port: 5432, Target: "192.168.1.50:5432", Note: "on the NAS"},
				{Name: "web", Proto: "tcp", Port: 8080},
			},
		},
	}

	out := toProtoNetMap(nm)
	if len(out.GetSelfServices()) != 2 {
		t.Fatalf("netmap carried %d services, want 2", len(out.GetSelfServices()))
	}
	got := map[string]*struct {
		proto  string
		port   uint32
		target string
	}{}
	for _, s := range out.GetSelfServices() {
		got[s.GetName()] = &struct {
			proto  string
			port   uint32
			target string
		}{s.GetProto(), s.GetPort(), s.GetTarget()}
	}
	db, ok := got["db"]
	if !ok {
		t.Fatal("db missing from the netmap")
	}
	// The target is the whole point: it is the address the node dials, and
	// getting it wrong is precisely what the self-check exists to reveal.
	if db.target != "192.168.1.50:5432" || db.port != 5432 || db.proto != "tcp" {
		t.Errorf("db = %+v, want tcp/5432 -> 192.168.1.50:5432", *db)
	}
	if web, ok := got["web"]; !ok || web.target != "" {
		// Empty target means 127.0.0.1:<port>; inventing one here would make the
		// node dial an address nobody declared.
		t.Errorf("web = %+v (present=%v), want an empty target", web, ok)
	}
}

// A node with nothing registered sends no service list, which is also what an
// older coordinator sends — the client must read the two the same way.
func TestNetMapWithNoServicesSendsNone(t *testing.T) {
	out := toProtoNetMap(&core.NetMap{Self: core.Node{ID: 1}})
	if len(out.GetSelfServices()) != 0 {
		t.Errorf("netmap carried %d services, want none", len(out.GetSelfServices()))
	}
}

// The two halves of a subnet alias go to different places, and that split IS the
// design: peers learn ONLY the stand-in prefix (learning the real CIDR would
// hand them back the collision the alias exists to remove), while the router
// itself learns both, because it is the only party that has to rewrite between
// them.
func TestNetMapSendsPeersTheAliasAndTheRouterBothHalves(t *testing.T) {
	real := netip.MustParsePrefix("192.168.1.0/24")
	alias := netip.MustParsePrefix("100.96.5.0/24")
	plain := netip.MustParsePrefix("10.9.0.0/16")

	router := core.Node{
		NodeKey:        core.Node{}.NodeKey, // zero key is fine; only routes matter here
		Overlay:        netip.MustParseAddr("100.64.0.4"),
		ApprovedRoutes: []netip.Prefix{real, plain},
		RouteAliases:   []core.RouteAlias{{Real: real, Alias: alias}},
	}

	// As a PEER of somebody else.
	nm := &core.NetMap{Self: core.Node{Overlay: netip.MustParseAddr("100.64.0.9")}, Peers: []core.Node{router}}
	out := toProtoNetMap(nm)
	if len(out.Peers) != 1 {
		t.Fatalf("peers: %d, want 1", len(out.Peers))
	}
	got := out.Peers[0].GetAllowedIps()
	want := map[string]bool{"100.64.0.4/32": true, alias.String(): true, plain.String(): true}
	if len(got) != len(want) {
		t.Fatalf("allowed_ips %v, want %v", got, want)
	}
	for _, ip := range got {
		if !want[ip] {
			t.Errorf("allowed_ips has %s, which peers must not be told", ip)
		}
		if ip == real.String() {
			t.Errorf("peers were told the REAL cidr %s — that is the collision the alias removes", real)
		}
	}
	// A peer is never told anyone else's mapping.
	if len(out.GetSubnetAliases()) != 0 {
		t.Errorf("a peer's netmap carries subnet_aliases %v", out.GetSubnetAliases())
	}

	// As ITSELF.
	own := toProtoNetMap(&core.NetMap{Self: router})
	as := own.GetSubnetAliases()
	if len(as) != 1 {
		t.Fatalf("self subnet_aliases: %v, want one", as)
	}
	if as[0].GetAlias() != alias.String() || as[0].GetReal() != real.String() {
		t.Errorf("subnet_alias = %s -> %s, want %s -> %s", as[0].GetAlias(), as[0].GetReal(), alias, real)
	}
}
