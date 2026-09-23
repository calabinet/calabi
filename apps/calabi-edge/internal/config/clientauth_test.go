package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// How an edge accepts a client: on the
// platform bff-edge verifies it; anywhere else the edge belongs to a self-hosted
// coordinator and accepts devices by its grants. The static token table that
// used to sit between the two is gone.

// testCoordKey is a well-formed base64 Ed25519 public key; config does not
// check it, the edge's main does.
const testCoordKey = "xMqLvONWcTdghKQ4cwvVQ81FuXDj/0npFphl4BujbdA="

// clearCalabiEnv blanks every CALABI_* variable (blank = unset to ApplyEnv and
// IsProduction), so the developer's shell can't decide a test's outcome.
func clearCalabiEnv(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "CALABI_") {
			t.Setenv(k, "")
		}
	}
}

func loadEffectiveYAML(t *testing.T, body string) (Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "edge.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, _, err := LoadEffective(p)
	return cfg, err
}

// Every platform edge's file says `accepted_tokens: []`, so an empty table still
// loads. A table with tokens is refused: parsing it silently would leave an
// operator believing its clients can still connect.
func TestRemovedTokenTableIsRefusedOnlyWhenItListsTokens(t *testing.T) {
	for name, body := range map[string]string{
		"key left out":  "node_label: n1\n",
		"empty list":    "node_label: n1\naccepted_tokens: []\n",
		"key, no value": "node_label: n1\naccepted_tokens:\n",
	} {
		if _, err := loadYAML(t, body); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	_, err := loadYAML(t, "node_label: n1\naccepted_tokens:\n  - token: s3cret\n    tenant_id: \"1\"\n")
	if err == nil || !strings.Contains(err.Error(), "no longer accepts tokens") {
		t.Fatalf("a token list loaded: err = %v", err)
	}
}

// An edge that could accept nobody refuses to start, and so does a standalone
// node that names no coordinator — its relay would otherwise serve anyone.
func TestEdgeThatCouldAcceptNobodyIsRefused(t *testing.T) {
	clearCalabiEnv(t)
	for _, c := range []struct {
		name, body string
		refused    string // "" = accepted
	}{
		{"standalone, no key", "mode: standalone\nnode_label: n1\n", "coordinator's public key"},
		{"no mode, no bff-edge", "node_label: n1\n", "mode: standalone"},
		{"no mode but a key", "node_label: n1\ncoord_pubkey: " + testCoordKey + "\n", "mode: standalone"},
		{"standalone relay, no key", "mode: standalone\nnode_label: r1\nregion: lax\nrole: relay\n", "coordinator's public key"},
		{"standalone with a key", "mode: standalone\nnode_label: n1\npublic:\n  host: n1.example\ncoord_pubkey: " + testCoordKey + "\n", ""},
		{"standalone with a key file", "mode: standalone\nnode_label: n1\npublic:\n  host: n1.example\ncoord_pubkey_file: /coord/coord.pub\n", ""},
		{"standalone, key in the relay block", "mode: standalone\nnode_label: n1\npublic:\n  host: n1.example\nrole: both\nrelay:\n  coord_pubkey: " + testCoordKey + "\n", ""},
		{"platform relay-only", "node_label: r1\nregion: lax\nrole: relay\nrelay:\n  kind: platform\n", ""},
		{"bff-edge verifies clients", "node_label: n1\npublic:\n  host: n1.example\nmulti_region:\n  mode: bff-edge\n", ""},
		{"standalone keeping bff-edge stays platform (BYOI)", "mode: standalone\nnode_label: n1\npublic:\n  host: n1.example\nmulti_region:\n  mode: bff-edge\n", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := loadEffectiveYAML(t, c.body)
			switch {
			case c.refused == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case c.refused != "" && err == nil:
				t.Fatal("accepted")
			case c.refused != "" && !strings.Contains(err.Error(), c.refused):
				t.Fatalf("refused, but not for %q: %v", c.refused, err)
			}
		})
	}
}

// With no config file the edge has no way to accept anyone; the environment can
// make it a standalone edge of a coordinator.
func TestConfigLessEdge(t *testing.T) {
	clearCalabiEnv(t)
	if _, _, err := LoadEffective(""); err == nil {
		t.Fatal("a config-less edge started with no way to accept a client")
	}
	t.Setenv("CALABI_EDGE_MODE", "standalone")
	t.Setenv("CALABI_EDGE_COORD_PUBKEY", testCoordKey)
	// A node with no file at all still has to say where it is.
	t.Setenv("CALABI_EDGE_PUBLIC_HOST", "edge.example")
	cfg, _, err := LoadEffective("")
	if err != nil {
		t.Fatalf("standalone by env with a key: %v", err)
	}
	if cfg.CoordPubKey != testCoordKey {
		t.Fatalf("coord_pubkey = %q", cfg.CoordPubKey)
	}
	t.Setenv("CALABI_EDGE_COORD_PUBKEY", "")
	t.Setenv("CALABI_EDGE_COORD_PUBKEY_FILE", "/coord/coord.pub")
	if cfg, _, err = LoadEffective(""); err != nil || cfg.CoordPubKeyFile != "/coord/coord.pub" {
		t.Fatalf("key file by env: %+v, %v", cfg.CoordPubKeyFile, err)
	}
}

// One coordinator key, whichever spelling gave it; two different answers are
// refused rather than one picked.
func TestCoordPubKeySpellings(t *testing.T) {
	clearCalabiEnv(t)
	const other = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	cfg, err := loadEffectiveYAML(t, "mode: standalone\nnode_label: n1\npublic:\n  host: n1.example\nrole: both\nrelay:\n  coord_pubkey: "+testCoordKey+"\n")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CoordPubKey != testCoordKey || cfg.Mesh.CoordPubKey != testCoordKey {
		t.Fatalf("relay.coord_pubkey not carried over: top %q relay %q", cfg.CoordPubKey, cfg.Mesh.CoordPubKey)
	}
	if _, err := loadEffectiveYAML(t, "mode: standalone\nnode_label: n1\npublic:\n  host: n1.example\nrole: both\ncoord_pubkey: "+testCoordKey+
		"\nrelay:\n  coord_pubkey: "+testCoordKey+"\n"); err != nil {
		t.Fatalf("the same key twice: %v", err)
	}
	if _, err := loadEffectiveYAML(t, "mode: standalone\nnode_label: n1\nrole: both\ncoord_pubkey: "+testCoordKey+
		"\nrelay:\n  coord_pubkey: "+other+"\n"); err == nil {
		t.Fatal("two different keys accepted")
	}
	if _, err := loadEffectiveYAML(t, "mode: standalone\nnode_label: n1\ncoord_pubkey: "+testCoordKey+
		"\ncoord_pubkey_file: /coord/coord.pub\n"); err == nil {
		t.Fatal("a key and a key file accepted")
	}
}

// A standalone node's relay serves its coordinator's devices only, whatever the
// file says; a platform relay keeps its own setting.
func TestStandaloneRelayRequiresGrants(t *testing.T) {
	clearCalabiEnv(t)
	cfg, err := loadEffectiveYAML(t, "mode: standalone\nnode_label: r1\nregion: lax\nrole: relay\ncoord_pubkey: "+
		testCoordKey+"\nrelay:\n  require_auth: false\n")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Mesh.RequireAuth {
		t.Fatal("a standalone relay does not require grants")
	}
	cfg, err = loadEffectiveYAML(t, "node_label: r1\nregion: lax\nrole: relay\nrelay:\n  kind: platform\n  require_auth: false\n")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mesh.RequireAuth {
		t.Fatal("a platform relay's require_auth was changed")
	}
}
