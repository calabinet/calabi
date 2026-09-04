package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Three config keys accept two spellings each: node_label (was node_id),
// edge_node_id and base_domain (were nested under tunnel: / http:). Every
// spelling loads; Load's job is to resolve to one value — leaving both copies
// equal for the two that kept their old nesting, since every reader in the
// codebase goes through it — and to refuse a config that spells the same field
// twice with two different values.

func loadYAML(t *testing.T, body string) (Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "edge.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return Load(p)
}

func TestNodeScopedTopLevelSpelling(t *testing.T) {
	// Note there is NO http.base_domain here. Default() seeds one
	// ("localtest.me"), so resolving against the merged config instead of the
	// file would see two values and reject a perfectly good config.
	c, err := loadYAML(t, "node_id: n1\nedge_node_id: 204\nbase_domain: lax.calabi.online\n")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.EdgeNodeID != 204 || c.Tunnel.EdgeNodeID != 204 {
		t.Errorf("edge id: top=%d nested=%d, want both 204", c.EdgeNodeID, c.Tunnel.EdgeNodeID)
	}
	if c.BaseDomain != "lax.calabi.online" || c.HTTP.BaseDomain != "lax.calabi.online" {
		t.Errorf("base domain: top=%q nested=%q, want both lax.calabi.online", c.BaseDomain, c.HTTP.BaseDomain)
	}
}

// Every config deployed today uses the nested spelling. It must keep loading
// unchanged, and must also populate the top-level copy.
func TestNodeScopedLegacyNesting(t *testing.T) {
	c, err := loadYAML(t, "node_id: n1\ntunnel:\n  edge_node_id: 104\nhttp:\n  base_domain: sgp.calabi.online\n")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.EdgeNodeID != 104 || c.Tunnel.EdgeNodeID != 104 {
		t.Errorf("edge id: top=%d nested=%d, want both 104", c.EdgeNodeID, c.Tunnel.EdgeNodeID)
	}
	if c.BaseDomain != "sgp.calabi.online" || c.HTTP.BaseDomain != "sgp.calabi.online" {
		t.Errorf("base domain: top=%q nested=%q, want both sgp.calabi.online", c.BaseDomain, c.HTTP.BaseDomain)
	}
}

func TestNodeScopedBothSpellingsAgreeing(t *testing.T) {
	c, err := loadYAML(t, "edge_node_id: 7\ntunnel:\n  edge_node_id: 7\nbase_domain: a.example\nhttp:\n  base_domain: A.EXAMPLE\n")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.EdgeNodeID != 7 || c.Tunnel.EdgeNodeID != 7 {
		t.Errorf("edge id: top=%d nested=%d, want both 7", c.EdgeNodeID, c.Tunnel.EdgeNodeID)
	}
	// Domains are case-insensitive, so the two spellings agree; the top-level
	// one wins so the value is at least self-consistent.
	if c.BaseDomain != "a.example" || c.HTTP.BaseDomain != "a.example" {
		t.Errorf("base domain: top=%q nested=%q, want both a.example", c.BaseDomain, c.HTTP.BaseDomain)
	}
}

// Two values for one field is a config bug whose consequences are silent — an
// edge registered under an id no client is shown, or one allocating subdomains
// on a domain it does not serve. Refuse to boot instead of picking a winner.
func TestNodeScopedConflictRejected(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"edge_node_id", "edge_node_id: 204\ntunnel:\n  edge_node_id: 104\n", "edge_node_id"},
		{"base_domain", "base_domain: a.example\nhttp:\n  base_domain: b.example\n", "base_domain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadYAML(t, tc.body)
			if err == nil {
				t.Fatalf("want error naming %s, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name %s", err, tc.want)
			}
		})
	}
}

// A config-less edge (dev / self-hosted) must stay self-consistent too.
func TestNodeScopedDefaultIsConsistent(t *testing.T) {
	d := Default()
	if d.BaseDomain != d.HTTP.BaseDomain {
		t.Errorf("Default: top=%q nested=%q, want equal", d.BaseDomain, d.HTTP.BaseDomain)
	}
	c, err := Load("")
	if err != nil {
		t.Fatalf("load empty path: %v", err)
	}
	if c.BaseDomain != c.HTTP.BaseDomain {
		t.Errorf("Load(\"\"): top=%q nested=%q, want equal", c.BaseDomain, c.HTTP.BaseDomain)
	}
}

// node_id was renamed to node_label because it sat one character away from
// edge_node_id while meaning something entirely different — a name, not a key.
// Every config deployed today still says node_id.
func TestNodeLabelSpellings(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"new", "node_label: lax-1\n"},
		{"legacy", "node_id: lax-1\n"},
		{"both agreeing", "node_label: lax-1\nnode_id: lax-1\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := loadYAML(t, tc.body)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if c.NodeLabel != "lax-1" {
				t.Errorf("node label = %q, want lax-1", c.NodeLabel)
			}
		})
	}
}

func TestNodeLabelConflictRejected(t *testing.T) {
	_, err := loadYAML(t, "node_label: lax-1\nnode_id: lax-2\n")
	if err == nil {
		t.Fatal("want error, got nil")
	}
	if !strings.Contains(err.Error(), "node_label") {
		t.Errorf("error %q does not name node_label", err)
	}
}

// A config that names the node in neither spelling keeps Default()'s name.
// Worth pinning: the BYOI wizard emits no name at all, so every BYOI edge
// registers under the same "edge-dev-1" label.
func TestNodeLabelFallsBackToDefault(t *testing.T) {
	c, err := loadYAML(t, "region: cd-vps\n")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.NodeLabel != Default().NodeLabel {
		t.Errorf("node label = %q, want Default() %q", c.NodeLabel, Default().NodeLabel)
	}
}
