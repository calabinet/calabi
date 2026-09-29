package config

import "testing"

// mesh.stun_port has three meanings: left out, 3478; 0, the STUN responder is
// off; anything else, that port. Left out and 0 are both a zero int once
// decoded, so the default lives in Default() and a file that writes 0
// overwrites it — the way `https_port: 0` turns HTTPS off.
//
// Until that, RelaySTUNPort read 0 as the default: `stun_port: 0` and
// CALABI_EDGE_RELAY_STUN_PORT=0 both left the responder answering on 3478, while
// the docs, the field's comment and a test called TestApplyEnvStunPortZeroDisables
// all said it was off. That test checked the field it had just set, never what
// the relay would do with it. These tests read the value every consumer reads —
// RelaySTUNPort, which starts the responder and is what the relay registers —
// from a file loaded the way the binary loads it.

// stunRelay is a relay-only node of a coordinator of your own, which
// LoadEffective accepts with nothing else configured.
const stunRelay = "mode: standalone\nnode_label: r1\nregion: lax\nrole: mesh\ncoord_pubkey: " + testCoordKey + "\n"

func TestSTUNPortFromTheFile(t *testing.T) {
	clearCalabiEnv(t)
	for _, c := range []struct {
		name, body string
		want       int
	}{
		{"no mesh block", stunRelay, 3478},
		{"mesh block without the key", stunRelay + "mesh:\n  derp_port: 3340\n", 3478},
		{"key with no value", stunRelay + "mesh:\n  stun_port:\n", 3478},
		{"0 turns it off", stunRelay + "mesh:\n  stun_port: 0\n", 0},
		{"a port of its own", stunRelay + "mesh:\n  stun_port: 3479\n", 3479},
		// Never documented, but it did keep the responder off, so it still does
		// — and the node still starts. Reported as 0: a negative port is refused
		// by the coordinator the relay registers with.
		{"negative is off, not refused", stunRelay + "mesh:\n  stun_port: -1\n", 0},
		// The pre-2.0.0 spelling of the block: the rename must carry an explicit
		// 0 across rather than drop it and fall back to the default.
		{"0 under the old relay: block", "mode: standalone\nnode_label: r1\nregion: lax\nrole: relay\ncoord_pubkey: " +
			testCoordKey + "\nrelay:\n  stun_port: 0\n", 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := loadEffectiveYAML(t, c.body)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if got := cfg.Mesh.RelaySTUNPort(); got != c.want {
				t.Errorf("RelaySTUNPort = %d, want %d", got, c.want)
			}
		})
	}
}

// The environment overrides the file both ways, and a blank variable is unset.
func TestSTUNPortFromTheEnvironment(t *testing.T) {
	for _, c := range []struct {
		name, file, env string
		want            int
	}{
		{"0 turns off a port the file set", "mesh:\n  stun_port: 3479\n", "0", 0},
		{"0 turns off the default", "", "0", 0},
		{"a port turns on what the file turned off", "mesh:\n  stun_port: 0\n", "3479", 3479},
		{"blank leaves the file's port", "mesh:\n  stun_port: 3479\n", "", 3479},
		{"blank leaves the file's 0", "mesh:\n  stun_port: 0\n", "", 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			clearCalabiEnv(t)
			t.Setenv("CALABI_EDGE_RELAY_STUN_PORT", c.env)
			cfg, err := loadEffectiveYAML(t, stunRelay+c.file)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if got := cfg.Mesh.RelaySTUNPort(); got != c.want {
				t.Errorf("RelaySTUNPort = %d, want %d", got, c.want)
			}
		})
	}
}

// A relay configured by the environment alone has no file to name the key in,
// so it gets the default — and CALABI_EDGE_RELAY_STUN_PORT=0 turns it off.
func TestSTUNPortWithNoConfigFile(t *testing.T) {
	clearCalabiEnv(t)
	t.Setenv("CALABI_EDGE_MODE", "standalone")
	t.Setenv("CALABI_EDGE_ROLE", "mesh")
	t.Setenv("CALABI_EDGE_COORD_PUBKEY", testCoordKey)
	cfg, _, err := LoadEffective("")
	if err != nil {
		t.Fatalf("config-less relay: %v", err)
	}
	if got := cfg.Mesh.RelaySTUNPort(); got != 3478 {
		t.Errorf("RelaySTUNPort = %d, want the default 3478", got)
	}
	t.Setenv("CALABI_EDGE_RELAY_STUN_PORT", "0")
	if cfg, _, err = LoadEffective(""); err != nil {
		t.Fatalf("config-less relay with STUN off: %v", err)
	}
	if got := cfg.Mesh.RelaySTUNPort(); got != 0 {
		t.Errorf("RelaySTUNPort = %d, want 0 (off)", got)
	}
}
