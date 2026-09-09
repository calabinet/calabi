package main

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// MagicDNS is OFF unless someone writes it down.
//
// THE DECISION THIS PINS. MagicDNS was withdrawn from every piece of
// customer-facing documentation on 2026-09-07 — the
// machines that want to type `ssh web-01.mesh` are overwhelmingly Windows and
// macOS, where it was never implemented. The CODE was deliberately left running
// on Linux, and on 2026-09-09 that bill came due: a daemon killed to swap its
// binary left /etc/resolv.conf pointing at a resolver that was no longer there,
// and the host had no DNS at all.
//
// A feature nobody is promised must not keep a failure mode that costs the whole
// machine. Turning the default around is the fix; the implementation stays for
// when split-horizon DNS (A1) revives it.
func TestMagicDNSIsOffUnlessAskedFor(t *testing.T) {
	var cfg localConfig
	if err := yaml.Unmarshal([]byte("mesh:\n  enabled: true\n  coord: coord.example:7014\n"), &cfg); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Mesh.MagicDNS {
		t.Fatal("a mesh config that never mentions magic_dns switched it on; " +
			"this daemon would rewrite /etc/resolv.conf without being asked")
	}
	if !cfg.Mesh.Enabled {
		t.Fatal("test is not exercising a live mesh config")
	}
}

// And the zero value, which is what every code path that builds a meshConfig
// without the field gets — including the platform daemon before it reads creds.
func TestTheZeroMeshConfigDoesNotTakeOverTheResolver(t *testing.T) {
	var cfg meshConfig
	if cfg.MagicDNS {
		t.Fatal("the zero meshConfig enables MagicDNS")
	}
}

// The switch must actually reach the config, or "off by default" would just mean
// "off, permanently" — and the next person would delete the flag as dead.
func TestMagicDNSCanStillBeTurnedOn(t *testing.T) {
	var cfg localConfig
	if err := yaml.Unmarshal([]byte("mesh:\n  enabled: true\n  magic_dns: true\n"), &cfg); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !cfg.Mesh.MagicDNS {
		t.Fatal("magic_dns: true did not reach meshConfig.MagicDNS")
	}
}
