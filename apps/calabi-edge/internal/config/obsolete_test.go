package config

import (
	"strings"
	"testing"
)

// The direct-dial settings are refused, in the two shapes they come in.
//
// An operator upgrading an existing edge has a YAML full of them. They parse
// fine and mean nothing now, and the consequence — an edge that looks wired to
// the control plane and is not — is exactly the kind of thing that goes
// unnoticed until somebody's tunnels stop being claimable.

// Whole blocks, where every field in them was an address.
func TestObsoleteDirectDialBlocksAreRefused(t *testing.T) {
	for _, block := range []string{"identity", "quota", "config_svc"} {
		t.Run(block, func(t *testing.T) {
			_, err := writeCfg(t, "node_label: edge-1\n"+block+":\n  addr: \"127.0.0.1:7001\"\n")
			if err == nil {
				t.Fatalf("%s: was accepted, but nothing reads it any more", block)
			}
			if !strings.Contains(err.Error(), block) {
				t.Errorf("error should name the dead block, got: %v", err)
			}
			if !strings.Contains(err.Error(), "multi_region") {
				t.Errorf("error should say what replaced it, got: %v", err)
			}
		})
	}
	// nats: never had an addr — it is dead in its entirety, and unlike the
	// others it used to be accepted in silence.
	if _, err := writeCfg(t, "node_label: edge-1\nnats:\n  url: \"nats://127.0.0.1:4222\"\n"); err == nil {
		t.Error("nats: was accepted; the edge has not subscribed to NATS directly since F3")
	}
}

// Single fields, in blocks that survive because they carry live settings too.
func TestObsoleteDirectDialFieldsAreRefused(t *testing.T) {
	for _, field := range []string{"tunnel", "cert"} {
		t.Run(field, func(t *testing.T) {
			_, err := writeCfg(t, "node_label: edge-1\n"+field+":\n  addr: \"127.0.0.1:7001\"\n")
			if err == nil {
				t.Fatalf("%s.addr was accepted, but nothing reads it any more", field)
			}
			if !strings.Contains(err.Error(), field+".addr") {
				t.Errorf("error should name the dead setting, got: %v", err)
			}
		})
	}
}

// TestLiveFieldsInTheSameStructsStillWork: the blocks carrying those dead
// addresses also carry live settings, so the check must key on the ADDRESS, not
// on the block being present.
//
// `cert:` no longer appears here. Every key it ever held is now refused — addr,
// refresh_seconds and org_id — so it is a block with nothing live left in it.
// The three stay itemised rather than collapsing into one dead BLOCK because
// their reasons differ, and the reason is the part an operator needs.
func TestLiveFieldsInTheSameStructsStillWork(t *testing.T) {
	cfg, err := writeCfg(t, `
node_label: edge-1
tunnel:
  edge_node_id: 100
  base_domain: live.example
multi_region:
  mode: "bff-edge"
  bff_edge_addr: "bff-edge:7080"
`)
	if err != nil {
		t.Fatalf("live settings in those blocks were rejected: %v", err)
	}
	if cfg.EdgeNodeID != 100 || cfg.Tunnel.BaseDomain != "live.example" {
		t.Fatalf("live settings lost: edge_node_id=%d base_domain=%q", cfg.EdgeNodeID, cfg.Tunnel.BaseDomain)
	}
	if !cfg.MultiRegion.IsBFFEdge() {
		t.Fatal("multi_region not parsed")
	}
}

// The two knobs removed in 2.0.0 are refused, not ignored.
//
// Neither was set in a single deployed config, both had a default, and both had
// to be carried through every change to the config layout. Deleting the fields
// would have been enough to stop them working — the decoder ignores keys it does
// not know — and that is precisely the outcome worth avoiding: an operator who
// sets a heartbeat cadence and gets the default is not told, and has no way to
// find out short of reading the source.
func TestRemovedKnobsAreRefused(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"presence interval", "presence:\n  interval_seconds: 20\n", "presence.interval_seconds"},
		{"cert refresh", "cert:\n  refresh_seconds: 45\n", "cert.refresh_seconds"},
		// Both spellings org_id ever had. It was a live setting that migrated
		// cert.org_id → org_id for exactly one release; a node's org now comes
		// from its own certificate and neither spelling means anything.
		{"org_id", "org_id: 7\n", "org_id"},
		{"cert.org_id", "cert:\n  org_id: 7\n", "cert.org_id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := writeCfg(t, "node_label: edge-1\n"+tc.body)
			if err == nil {
				t.Fatalf("%s was accepted; it does nothing, so the operator is misled", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the error should name the setting: %v", err)
			}
		})
	}
}
