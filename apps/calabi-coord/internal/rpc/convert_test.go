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
