package config

import (
	"strings"
	"testing"
)

// TestObsoleteDirectDialIsRefused: an operator upgrading an existing edge has a
// YAML full of identity.addr / tunnel.addr. Those parse fine and mean nothing
// now, and the consequence — clients authenticated off the static token table
// instead of identity-svc — is exactly the kind of thing that goes unnoticed.
func TestObsoleteDirectDialIsRefused(t *testing.T) {
	for _, field := range []string{"identity", "tunnel", "cert", "quota", "config_svc"} {
		t.Run(field, func(t *testing.T) {
			_, err := writeCfg(t, "node_label: edge-1\n"+field+":\n  addr: \"127.0.0.1:7001\"\n")
			if err == nil {
				t.Fatalf("%s.addr was accepted, but nothing reads it any more", field)
			}
			if !strings.Contains(err.Error(), field+".addr") {
				t.Errorf("error should name the dead setting, got: %v", err)
			}
			if !strings.Contains(err.Error(), "multi_region") {
				t.Errorf("error should say what replaced it, got: %v", err)
			}
		})
	}
}

// TestLiveFieldsInTheSameStructsStillWork: the structs carrying those dead
// addresses also carry live settings, so the check must key on the ADDRESS, not
// on the block being present.
func TestLiveFieldsInTheSameStructsStillWork(t *testing.T) {
	cfg, err := writeCfg(t, `
node_label: edge-1
tunnel:
  edge_node_id: 100
cert:
  org_id: 7
multi_region:
  mode: "bff-edge"
  bff_edge_addr: "bff-edge:7080"
`)
	if err != nil {
		t.Fatalf("live settings in those blocks were rejected: %v", err)
	}
	if cfg.Tunnel.EdgeNodeID != 100 || cfg.Cert.OrgID != 7 {
		t.Fatalf("live settings lost: edge_node_id=%d org_id=%d", cfg.Tunnel.EdgeNodeID, cfg.Cert.OrgID)
	}
	if !cfg.MultiRegion.IsBFFEdge() {
		t.Fatal("multi_region not parsed")
	}
}
