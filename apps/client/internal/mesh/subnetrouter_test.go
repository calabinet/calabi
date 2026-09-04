package mesh

import (
	"net/netip"
	"strings"
	"testing"
)

func mustPfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// A subnet CIDR and an exit-node (0.0.0.0/0) advertisement produce the right
// iptables MASQUERADE rules; IPv6 is skipped (v0 is IPv4-only).
func TestIptablesMasqueradeRules(t *testing.T) {
	rules := iptablesMasqueradeRules([]netip.Prefix{
		mustPfx("192.168.1.0/24"),
		mustPfx("0.0.0.0/0"),
		mustPfx("fd00::/8"), // skipped
	})
	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2 (v4 only): %v", len(rules), rules)
	}
	subnet := strings.Join(rules[0], " ")
	if !strings.Contains(subnet, "-s "+meshOverlayCIDR) || !strings.Contains(subnet, "-d 192.168.1.0/24") ||
		!strings.Contains(subnet, "MASQUERADE") {
		t.Fatalf("subnet rule wrong: %s", subnet)
	}
	exit := strings.Join(rules[1], " ")
	if !strings.Contains(exit, "! -d "+meshOverlayCIDR) || !strings.Contains(exit, "MASQUERADE") {
		t.Fatalf("exit rule wrong: %s", exit)
	}
}

// The nft rule bodies mirror the iptables semantics: subnet → daddr <cidr>,
// exit → daddr != overlay.
func TestNftMasqueradeRules(t *testing.T) {
	rules := nftMasqueradeRules([]netip.Prefix{
		mustPfx("192.168.1.0/24"),
		mustPfx("0.0.0.0/0"),
	})
	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2: %v", len(rules), rules)
	}
	if rules[0] != "ip saddr "+meshOverlayCIDR+" ip daddr 192.168.1.0/24 masquerade" {
		t.Fatalf("subnet nft rule wrong: %q", rules[0])
	}
	if rules[1] != "ip saddr "+meshOverlayCIDR+" ip daddr != "+meshOverlayCIDR+" masquerade" {
		t.Fatalf("exit nft rule wrong: %q", rules[1])
	}
}
