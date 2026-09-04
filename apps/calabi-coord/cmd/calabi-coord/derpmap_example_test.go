package main

import "testing"

// The shipped example map must actually parse: an operator copies it to start a
// relay fleet, and a CALABI_COORD_DERP_MAP_FILE that fails to load is a hard
// startup error.
//
// It lives in this module (apps/calabi-coord/examples/) rather than under
// deploy/compose/, so it travels with the coordinator into the public tree — a
// self-hoster needs the example more than we do, and a test that reads across
// the module boundary breaks the moment the module ships on its own.
func TestExampleDERPMapFileParses(t *testing.T) {
	m, home, err := readDERPMapFile("../../examples/derp-map.example.json", "")
	if err != nil {
		t.Fatalf("example derp map: %v", err)
	}
	if len(m.Regions) != 3 || home != "lax" {
		t.Fatalf("parsed %d regions, home %q; want 3 regions, home lax", len(m.Regions), home)
	}
	for _, r := range m.Regions {
		if len(r.Nodes) != 1 || r.Nodes[0].STUNPort == 0 {
			t.Fatalf("region %s must advertise a STUN port or clients can never measure (and so never choose) it: %+v", r.Code, r.Nodes)
		}
	}
}
