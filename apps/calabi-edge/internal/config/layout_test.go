package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The old layout and the new one must produce the SAME Config.
//
// This is the test the 1.15.0 layout change stands on. Everything else checks a
// rule; this checks the outcome an operator cares about — that upgrading the
// binary under an unchanged file changes nothing about how the node behaves.
//
// It is written as two spellings of one node rather than as per-key assertions
// on purpose: a per-key list is a whitelist, and a whitelist is what fails open
// when somebody adds a setting and forgets this file. DeepEqual over the whole
// struct cannot be forgotten.
func TestOldLayoutLoadsIdenticallyToNew(t *testing.T) {
	const oldLayout = `
node_id: lax-1
region: lax
role: both
mode: standalone
coord_pubkey: "` + testCoordKey + `"
edge_node_id: 42
base_domain: lax.example.com
control:
  addr: ":7443"
http:
  addr: ":80"
https:
  addr: ":443"
  self_signed: true
sni:
  addr: ":8443"
peer_forward:
  forward_addr: ":7090"
  advertise_addr: "10.0.1.5:7090"
relay:
  derp_port: 3340
  stun_port: 3478
  label: lax
  kind: self
public:
  addr: "edge-lax.example.com:7443"
state:
  dir: /var/lib/calabi-edge
admin:
  addr: "127.0.0.1:9101"
log:
  level: debug
  format: json
`
	// The 1.15 layout: services split, listeners still configured by `addr`.
	const midLayout = `
node_label: lax-1
region: lax
role: both
mode: standalone
coord_pubkey: "` + testCoordKey + `"
edge_node_id: 42
tunnel:
  base_domain: lax.example.com
  control:
    addr: ":7443"
  http:
    addr: ":80"
  https:
    addr: ":443"
    self_signed: true
  sni:
    addr: ":8443"
  peer_forward:
    forward_addr: ":7090"
    advertise_addr: "10.0.1.5:7090"
mesh:
  derp_port: 3340
  stun_port: 3478
  label: lax
  kind: self
public:
  addr: "edge-lax.example.com:7443"
state:
  dir: /var/lib/calabi-edge
admin:
  addr: "127.0.0.1:9101"
log:
  level: debug
  format: json
`
	// The current one: one address for the node, a port per service.
	const newLayout = `
node_label: lax-1
region: lax
role: both
mode: standalone
coord_pubkey: "` + testCoordKey + `"
edge_node_id: 42
public:
  host: edge-lax.example.com
tunnel:
  base_domain: lax.example.com
  control_port: 7443
  http_port: 80
  https_port: 443
  https_self_signed: true
  sni_port: 8443
  peer_forward:
    forward_addr: ":7090"
    advertise_addr: "10.0.1.5:7090"
mesh:
  derp_port: 3340
  stun_port: 3478
  label: lax
  kind: self
state:
  dir: /var/lib/calabi-edge
admin:
  addr: "127.0.0.1:9101"
log:
  level: debug
  format: json
`
	a, err := writeCfg(t, oldLayout)
	if err != nil {
		t.Fatalf("the pre-1.15 layout no longer loads: %v", err)
	}
	m, err := writeCfg(t, midLayout)
	if err != nil {
		t.Fatalf("the 1.15 layout no longer loads: %v", err)
	}
	b, err := writeCfg(t, newLayout)
	if err != nil {
		t.Fatalf("the current layout does not load: %v", err)
	}
	if !reflect.DeepEqual(a, m) {
		t.Errorf("the pre-1.15 and 1.15 layouts of one node produce different configs:\n pre: %+v\n 1.15: %+v", a, m)
	}
	if !reflect.DeepEqual(m, b) {
		t.Errorf("the 1.15 and current layouts of one node produce different configs:\n 1.15: %+v\n new: %+v", m, b)
	}

	// And spot-check that the values actually arrived, so a migration that
	// dropped both sides equally could not pass the comparison above.
	switch {
	case a.NodeLabel != "lax-1":
		t.Errorf("node_label = %q", a.NodeLabel)
	case a.EdgeNodeID != 42:
		t.Errorf("edge_node_id = %d", a.EdgeNodeID)
	case a.Tunnel.BaseDomain != "lax.example.com":
		t.Errorf("base domain = %q", a.Tunnel.BaseDomain)
	case a.Tunnel.ControlAddr() != ":7443" || a.Tunnel.HTTPSAddr() != ":443" || a.Tunnel.SNIAddr() != ":8443":
		t.Errorf("listeners = %+v", a.Tunnel)
	case !a.PeerForwardEnabled():
		t.Errorf("peer forwarding off: %+v", a.Tunnel.PeerForward)
	case a.Mesh.DERPPort != 3340 || a.Mesh.Label != "lax" || a.Mesh.Kind != "self":
		t.Errorf("mesh = %+v", a.Mesh)
	}
}

// A node that only joins the mesh can now write a file with no tunnel: block at
// all — which is the point of the split. Before it, the same node's config was
// indistinguishable from an edge's.
func TestMeshOnlyConfigNeedsNoTunnelBlock(t *testing.T) {
	cfg, err := writeCfg(t, `
node_label: relay-1
region: hk
role: mesh
mesh:
  kind: self
  derp_port: 3340
`)
	if err != nil {
		t.Fatalf("a mesh-only config was rejected: %v", err)
	}
	if !cfg.ServesMesh() || cfg.ServesTunnels() {
		t.Fatalf("role: mesh should serve the mesh only")
	}
	if cfg.Mesh.Label != "hk" {
		t.Errorf("mesh.label should default to the region, got %q", cfg.Mesh.Label)
	}
}

// Both spellings of one setting in one file: refuse, never pick.
//
// An operator mid-migration has the old key left behind and the new one added,
// and the two will not agree — that is why they are editing. Choosing one
// silently is how a node comes back on a port nobody expected.
func TestBothLayoutsInOneFileAreRefused(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"nested block twice", "http:\n  addr: \":80\"\ntunnel:\n  http:\n    addr: \":8080\"\n", "http"},
		{"renamed block twice", "relay:\n  kind: self\nmesh:\n  kind: platform\n", "mesh"},
		// org_id used to be the hoisted-key case here (org_id vs cert.org_id).
		// Both spellings are refused outright now, so a file saying it twice is
		// covered by TestRemovedKnobsAreRefused instead. edge_node_id is the
		// remaining hoist and carries the same "says it twice" risk.
		{"hoisted key twice", "edge_node_id: 1\ntunnel:\n  edge_node_id: 2\n", "edge_node_id"},
		{"node name twice", "node_label: a\nnode_id: b\n", "node_label"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := writeCfg(t, "region: lax\n"+tc.body)
			if err == nil {
				t.Fatal("a file that says the same setting twice was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the error should name %q: %v", tc.want, err)
			}
		})
	}
}

// Agreeing duplicates are fine — a file that says the same thing twice is not
// ambiguous, and refusing it would fail an upgrade for no reason.
func TestAgreeingDuplicatesAreAccepted(t *testing.T) {
	cfg, err := writeCfg(t, "region: lax\nnode_label: a\nnode_id: a\nedge_node_id: 9\ntunnel:\n  edge_node_id: 9\n")
	if err != nil {
		t.Fatalf("agreeing spellings were refused: %v", err)
	}
	if cfg.NodeLabel != "a" || cfg.EdgeNodeID != 9 {
		t.Errorf("got %q / %d", cfg.NodeLabel, cfg.EdgeNodeID)
	}
}

// The retired `mesh:` peer-forward block is refused by name.
//
// It configured edge-to-edge forwarding of TUNNEL traffic and has nothing to do
// with the mesh; `mesh:` now means the relay. Migrating it by guessing from its
// fields would be a guess made on a production node, and the spelling never
// shipped outside configs we deploy ourselves — so it is an error with the new
// name in it instead.
func TestRetiredMeshPeerForwardBlockIsRefused(t *testing.T) {
	_, err := writeCfg(t, "node_label: edge-1\nmesh:\n  forward_addr: \":7090\"\n  advertise_addr: \"10.0.1.5:7090\"\n")
	if err == nil {
		t.Fatal("mesh.forward_addr was accepted as a mesh-relay setting")
	}
	if !strings.Contains(err.Error(), "tunnel.peer_forward") {
		t.Errorf("the error should say where it moved to: %v", err)
	}
}

// Every deployed config we hold must load under the new layout, and keep the
// settings it had. The files are still written in the old layout — supported,
// and not worth rewriting a production file for — so this is also the proof
// that support is real rather than asserted in a unit test's fixture.
func TestDeployedConfigsSurviveTheLayoutChange(t *testing.T) {
	paths, err := filepath.Glob("../../../../deploy/dev/edge*.yaml")
	if err != nil || len(paths) == 0 {
		t.Fatalf("no dev edge configs found (glob wrong, not the rig empty): %v", err)
	}
	more, _ := filepath.Glob("../../../../deploy/compose/edge/*/*.yaml")
	paths = append(paths, more...)

	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		cfg, err := Load(p)
		if err != nil {
			t.Errorf("%s no longer loads: %v", p, err)
			continue
		}
		// Whatever the file says it listens on, it must still listen on.
		if strings.Contains(string(raw), "control:") && cfg.Tunnel.ControlAddr() == "" {
			t.Errorf("%s sets a control listener but it did not survive the layout migration", p)
		}
		if strings.Contains(string(raw), "derp_port:") && cfg.Mesh.DERPPort == 0 {
			t.Errorf("%s sets a relay port but it did not survive the layout migration", p)
		}
		if strings.Contains(string(raw), "forward_addr:") && !cfg.PeerForwardEnabled() {
			t.Errorf("%s sets peer forwarding but it did not survive the layout migration", p)
		}
	}
}
