package mesh

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
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
	subnet := strings.Join(rules[0].args("-A", ""), " ")
	if subnet != "-t nat -A POSTROUTING -s "+meshOverlayCIDR+" -d 192.168.1.0/24 -j MASQUERADE" {
		t.Fatalf("subnet rule wrong: %s", subnet)
	}
	exit := strings.Join(rules[1].args("-A", ""), " ")
	if exit != "-t nat -A POSTROUTING -s "+meshOverlayCIDR+" ! -d "+meshOverlayCIDR+" -j MASQUERADE" {
		t.Fatalf("exit rule wrong: %s", exit)
	}
	tagged := strings.Join(rules[0].args("-D", "calabi-mesh-0011223344556677"), " ")
	if tagged != "-t nat -D POSTROUTING -s "+meshOverlayCIDR+" -d 192.168.1.0/24 -m comment --comment calabi-mesh-0011223344556677 -j MASQUERADE" {
		t.Fatalf("tagged rule wrong: %s", tagged)
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

// The owner names must survive the tools that print them back: a comment
// iptables would quote in -S output could never be matched by reclaim, and nft
// refuses table names past 32 characters on older kernels.
func TestNATOwnerNamesAreSafe(t *testing.T) {
	var k meshproto.NodeKey
	for i := range k {
		k[i] = 0xff
	}
	c := iptablesOwnerComment(k)
	if strings.Trim(c, "abcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
		t.Errorf("comment %q holds characters iptables would quote in -S output", c)
	}
	if tbl := nftTableFor(k); len(tbl) > 32 {
		t.Errorf("nft table %q is %d characters, over 32", tbl, len(tbl))
	}
	if iptablesOwnerComment(testNode(1)) == iptablesOwnerComment(testNode(2)) {
		t.Error("two nodes got the same owner comment")
	}
}

// --- a model of the nat table -------------------------------------------------

// fakeIptables models just enough of `iptables -t nat` for the installer: -A
// appends, -D removes the FIRST exact match or fails like iptables does, and -S
// prints the chain the way iptables does, quoting a comment that needs it.
//
// The real tool is exercised by the same scenarios through
// TestSubnetRouterNAT_RealNetfilter (subnetrouter_linux_test.go), which is what
// keeps this model honest.
type fakeIptables struct {
	chains    map[string][][]string
	noComment bool                // the comment match is not available
	failOn    func([]string) bool // refuse this -A
}

func newFakeIptables() *fakeIptables { return &fakeIptables{chains: map[string][][]string{}} }

func (f *fakeIptables) run(args ...string) ([]byte, error) {
	if len(args) < 4 || args[0] != "-t" || args[1] != "nat" {
		return nil, fmt.Errorf("fake iptables: unexpected args %q", args)
	}
	verb, chain, spec := args[2], args[3], args[4:]
	switch verb {
	case "-S":
		var b strings.Builder
		fmt.Fprintf(&b, "-P %s ACCEPT\n", chain)
		for _, r := range f.chains[chain] {
			words := slices.Clone(r)
			for i := 1; i < len(words); i++ {
				if words[i-1] == "--comment" && strings.Trim(words[i], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != "" {
					words[i] = `"` + words[i] + `"`
				}
			}
			fmt.Fprintf(&b, "-A %s %s\n", chain, strings.Join(words, " "))
		}
		return []byte(b.String()), nil
	case "-A":
		if f.noComment && slices.Contains(spec, "comment") {
			return []byte("iptables v1.8.10 (legacy): Couldn't load match `comment':No such file or directory"), errors.New("exit status 2")
		}
		if f.failOn != nil && f.failOn(spec) {
			return []byte("iptables: No chain/target/match by that name."), errors.New("exit status 1")
		}
		f.chains[chain] = append(f.chains[chain], slices.Clone(spec))
		return nil, nil
	case "-D":
		for i, r := range f.chains[chain] {
			if slices.Equal(r, spec) {
				f.chains[chain] = slices.Delete(f.chains[chain], i, i+1)
				return nil, nil
			}
		}
		return []byte("iptables: Bad rule (does a matching rule exist in that chain?)."), errors.New("exit status 1")
	}
	return nil, fmt.Errorf("fake iptables: unexpected verb %q", verb)
}

// iptablesHarness is a place to run the scenarios: the model everywhere, and
// real iptables where the Linux test file adds it.
type iptablesHarness struct {
	name string
	run  iptablesRunner
}

// realIptablesHarnesses is filled in by subnetrouter_linux_test.go when the
// environment says it is safe to program netfilter.
var realIptablesHarnesses func(t *testing.T) []iptablesHarness

func iptablesHarnesses(t *testing.T) []iptablesHarness {
	hs := []iptablesHarness{{"model", newFakeIptables().run}}
	if realIptablesHarnesses != nil {
		hs = append(hs, realIptablesHarnesses(t)...)
	}
	return hs
}

// chainRules lists a chain through -S, the way an operator would look.
func chainRules(t *testing.T, run iptablesRunner, chain string) []string {
	t.Helper()
	out, err := run("-t", "nat", "-S", chain)
	if err != nil {
		t.Fatalf("iptables -S %s: %v: %s", chain, err, out)
	}
	var rules []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.HasPrefix(line, "-A ") {
			rules = append(rules, line)
		}
	}
	return rules
}

func countContaining(rules []string, parts ...string) int {
	n := 0
next:
	for _, r := range rules {
		for _, p := range parts {
			if !strings.Contains(r, p) {
				continue next
			}
		}
		n++
	}
	return n
}

func testNode(b byte) meshproto.NodeKey {
	var k meshproto.NodeKey
	for i := range k {
		k[i] = b
	}
	return k
}

// Test-only address space (RFC 2544 benchmarking), so the real-netfilter run
// can never be confused with anything a host really forwards.
const (
	testLAN     = "198.18.1.0/24"
	testLAN2    = "198.18.2.0/24"
	testAlias   = "100.96.201.0/24"
	testAlias2  = "100.96.202.0/24"
	legacyRule  = "-s 100.64.0.0/10 -d " + testLAN + " -j MASQUERADE"
	operatorNet = "198.19.0.0/16"
)

// THE FIELD REPORT (2026-09-17): a subnet router whose daemon exited without
// running its cleanup, again and again, had ~40 identical MASQUERADE rules. The
// daemon's next start must leave exactly one rule per route, whether the
// leftovers were written by this release (tagged) or an earlier one (untagged),
// and must not touch rules that are not its own.
func TestSubnetRouterNATDoesNotAccumulateAcrossUncleanExits(t *testing.T) {
	for _, h := range iptablesHarnesses(t) {
		t.Run(h.name, func(t *testing.T) {
			be := iptablesNAT{run: h.run}
			node := testNode(1)
			routes := []netip.Prefix{mustPfx(testLAN), mustPfx("0.0.0.0/0")}

			// The host as found: 40 copies from releases before owner comments,
			// plus a rule the operator (or podman) owns.
			for range 40 {
				if _, err := h.run("-t", "nat", "-A", "POSTROUTING", "-s", "100.64.0.0/10", "-d", testLAN, "-j", "MASQUERADE"); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := h.run("-t", "nat", "-A", "POSTROUTING", "-s", operatorNet, "!", "-d", operatorNet, "-j", "MASQUERADE"); err != nil {
				t.Fatal(err)
			}

			var cleanup func()
			for start := 1; start <= 5; start++ {
				c, reclaimed, err := be.masquerade(node, routes)
				if err != nil {
					t.Fatalf("start %d: %v", start, err)
				}
				switch start {
				case 1:
					if reclaimed != 40 {
						t.Errorf("first start reclaimed %d rules, want the 40 legacy copies", reclaimed)
					}
				default:
					if reclaimed != 2 {
						t.Errorf("start %d reclaimed %d rules, want the 2 the killed run left", start, reclaimed)
					}
				}
				cleanup = c // and then the daemon is killed: cleanup never runs
			}

			rules := chainRules(t, h.run, "POSTROUTING")
			if n := countContaining(rules, "-d "+testLAN); n != 1 {
				t.Errorf("%d rules for %s after 5 unclean restarts, want 1:\n%s", n, testLAN, strings.Join(rules, "\n"))
			}
			if n := countContaining(rules, "! -d 100.64.0.0/10", "MASQUERADE"); n != 1 {
				t.Errorf("%d exit-node rules after 5 unclean restarts, want 1:\n%s", n, strings.Join(rules, "\n"))
			}
			if n := countContaining(rules, operatorNet); n != 1 {
				t.Errorf("the operator's own rule was touched:\n%s", strings.Join(rules, "\n"))
			}

			cleanup() // the last run stops gracefully
			rules = chainRules(t, h.run, "POSTROUTING")
			if n := countContaining(rules, "100.64.0.0/10"); n != 0 {
				t.Errorf("%d overlay rules left after a graceful stop, want 0:\n%s", n, strings.Join(rules, "\n"))
			}
			if n := countContaining(rules, operatorNet); n != 1 {
				t.Errorf("cleanup touched the operator's own rule:\n%s", strings.Join(rules, "\n"))
			}
			_, _ = h.run("-t", "nat", "-D", "POSTROUTING", "-s", operatorNet, "!", "-d", operatorNet, "-j", "MASQUERADE")
		})
	}
}

// Two clients on one machine (--service-name) advertising the same subnet each
// hold a copy. One restarting uncleanly reclaims only its own, and one stopping
// leaves the other forwarding.
func TestSubnetRouterNATTwoClientsOnOneMachine(t *testing.T) {
	for _, h := range iptablesHarnesses(t) {
		t.Run(h.name, func(t *testing.T) {
			be := iptablesNAT{run: h.run}
			a, b := testNode(1), testNode(2)
			routes := []netip.Prefix{mustPfx(testLAN)}

			cleanupB, _, err := be.masquerade(b, routes)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := be.masquerade(a, routes); err != nil {
				t.Fatal(err)
			}
			cleanupA, reclaimed, err := be.masquerade(a, routes) // A was killed and restarts
			if err != nil {
				t.Fatal(err)
			}
			if reclaimed != 1 {
				t.Errorf("A's restart reclaimed %d rules, want only its own 1", reclaimed)
			}
			rules := chainRules(t, h.run, "POSTROUTING")
			if n := countContaining(rules, "-d "+testLAN); n != 2 {
				t.Fatalf("%d rules for %s, want one per client:\n%s", n, testLAN, strings.Join(rules, "\n"))
			}

			cleanupA()
			rules = chainRules(t, h.run, "POSTROUTING")
			if n := countContaining(rules, "-d "+testLAN, iptablesOwnerComment(b)); n != 1 {
				t.Errorf("A stopping took B's forwarding with it:\n%s", strings.Join(rules, "\n"))
			}
			if n := countContaining(rules, "-d "+testLAN); n != 1 {
				t.Errorf("%d rules for %s after A stopped, want B's 1:\n%s", n, testLAN, strings.Join(rules, "\n"))
			}
			cleanupB()
			if n := countContaining(chainRules(t, h.run, "POSTROUTING"), "100.64.0.0/10"); n != 0 {
				t.Errorf("%d overlay rules left after both stopped", n)
			}
		})
	}
}

// A route withdrawn while the daemon was down leaves a rule no later install
// spells again; the owner comment is what lets the next start find it.
func TestSubnetRouterNATReclaimsARouteWithdrawnWhileDown(t *testing.T) {
	for _, h := range iptablesHarnesses(t) {
		t.Run(h.name, func(t *testing.T) {
			be := iptablesNAT{run: h.run}
			node := testNode(1)
			if _, _, err := be.masquerade(node, []netip.Prefix{mustPfx(testLAN), mustPfx("0.0.0.0/0")}); err != nil {
				t.Fatal(err)
			}
			// Killed; the operator turns the exit node off and moves the subnet.
			cleanup, _, err := be.masquerade(node, []netip.Prefix{mustPfx(testLAN2)})
			if err != nil {
				t.Fatal(err)
			}
			rules := chainRules(t, h.run, "POSTROUTING")
			if n := countContaining(rules, "100.64.0.0/10"); n != 1 || countContaining(rules, "-d "+testLAN2) != 1 {
				t.Errorf("want only the %s rule, got:\n%s", testLAN2, strings.Join(rules, "\n"))
			}
			cleanup()
		})
	}
}

// The alias rewrite is installed per control-plane session and has the same
// install/cleanup shape, so it leaks the same way. It must also not reclaim the
// MASQUERADE rules, which belong to the longer-lived data plane — and the other
// way round.
func TestSubnetAliasNATDoesNotAccumulateAcrossUncleanExits(t *testing.T) {
	for _, h := range iptablesHarnesses(t) {
		t.Run(h.name, func(t *testing.T) {
			be := iptablesNAT{run: h.run}
			node := testNode(1)
			masqCleanup, _, err := be.masquerade(node, []netip.Prefix{mustPfx(testLAN)})
			if err != nil {
				t.Fatal(err)
			}
			aliases := []SubnetAlias{{Alias: mustPfx(testAlias), Real: mustPfx(testLAN)}}
			for range 5 {
				if _, _, err := be.aliasRewrite(node, aliases); err != nil {
					t.Fatal(err)
				}
			}
			// The coordinator hands out a different alias after the restart.
			aliases = []SubnetAlias{{Alias: mustPfx(testAlias2), Real: mustPfx(testLAN)}}
			aliasCleanup, _, err := be.aliasRewrite(node, aliases)
			if err != nil {
				t.Fatal(err)
			}
			pre := chainRules(t, h.run, "PREROUTING")
			if n := countContaining(pre, "NETMAP"); n != 1 || countContaining(pre, "-d "+testAlias2) != 1 {
				t.Errorf("want exactly the %s rewrite, got:\n%s", testAlias2, strings.Join(pre, "\n"))
			}
			if n := countContaining(chainRules(t, h.run, "POSTROUTING"), "-d "+testLAN); n != 1 {
				t.Errorf("installing the alias rewrite disturbed the MASQUERADE rule (%d copies)", n)
			}

			if _, _, err := be.masquerade(node, []netip.Prefix{mustPfx(testLAN)}); err != nil { // data plane restarts
				t.Fatal(err)
			}
			if n := countContaining(chainRules(t, h.run, "PREROUTING"), "NETMAP"); n != 1 {
				t.Errorf("installing MASQUERADE disturbed the alias rewrite (%d rules)", n)
			}

			aliasCleanup()
			masqCleanup()
			if n := countContaining(chainRules(t, h.run, "PREROUTING"), "NETMAP"); n != 0 {
				t.Errorf("%d rewrites left after cleanup", n)
			}
		})
	}
}

// A kernel without the comment match still forwards (untagged, as before), and
// still does not accumulate: the untagged sweep removes the killed run's copy.
func TestSubnetRouterNATWithoutTheCommentMatch(t *testing.T) {
	f := newFakeIptables()
	f.noComment = true
	be := iptablesNAT{run: f.run}
	routes := []netip.Prefix{mustPfx(testLAN)}
	var cleanup func()
	for range 5 {
		c, _, err := be.masquerade(testNode(1), routes)
		if err != nil {
			t.Fatalf("no comment match must not stop forwarding: %v", err)
		}
		cleanup = c
	}
	rules := chainRules(t, f.run, "POSTROUTING")
	if len(rules) != 1 || !strings.HasSuffix(rules[0], legacyRule) {
		t.Fatalf("want one untagged rule, got:\n%s", strings.Join(rules, "\n"))
	}
	cleanup()
	if rules := chainRules(t, f.run, "POSTROUTING"); len(rules) != 0 {
		t.Fatalf("left after cleanup:\n%s", strings.Join(rules, "\n"))
	}
}

// A rule that will not go in takes the ones before it out again, and the error
// names it.
func TestSubnetRouterNATRollsBackAPartialInstall(t *testing.T) {
	f := newFakeIptables()
	f.failOn = func(spec []string) bool { return slices.Contains(spec, testLAN2) }
	_, _, err := iptablesNAT{run: f.run}.masquerade(testNode(1), []netip.Prefix{mustPfx(testLAN), mustPfx(testLAN2)})
	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.HasPrefix(err.Error(), "iptables masquerade [-t nat -A POSTROUTING") || !strings.Contains(err.Error(), testLAN2) {
		t.Errorf("error does not name the refused rule: %v", err)
	}
	if rules := chainRules(t, f.run, "POSTROUTING"); len(rules) != 0 {
		t.Errorf("partial install left behind:\n%s", strings.Join(rules, "\n"))
	}
}

// --- nft backend ----------------------------------------------------------------

// fakeNft models tables holding nat postrouting rules.
type fakeNft struct{ tables map[string][]string }

func (f *fakeNft) run(args ...string) ([]byte, error) {
	switch {
	case len(args) == 4 && args[0] == "delete" && args[1] == "table":
		if _, ok := f.tables[args[3]]; !ok {
			return []byte("Error: No such file or directory"), errors.New("exit status 1")
		}
		delete(f.tables, args[3])
	case len(args) == 4 && args[0] == "add" && args[1] == "table":
		if _, ok := f.tables[args[3]]; !ok {
			f.tables[args[3]] = []string{}
		}
	case len(args) > 4 && args[0] == "add" && args[1] == "chain":
		if _, ok := f.tables[args[3]]; !ok {
			return []byte("Error: No such file or directory"), errors.New("exit status 1")
		}
	case len(args) > 5 && args[0] == "add" && args[1] == "rule":
		if _, ok := f.tables[args[3]]; !ok {
			return []byte("Error: No such file or directory"), errors.New("exit status 1")
		}
		f.tables[args[3]] = append(f.tables[args[3]], strings.Join(args[5:], " "))
	default:
		return nil, fmt.Errorf("fake nft: unexpected args %q", args)
	}
	return nil, nil
}

// The nft backend keeps each node in a table of its own. A killed run's table is
// replaced rather than duplicated, the pre-owner shared table is cleared, and one
// client's start or stop leaves another client's table alone — which the old
// single shared table could not do.
func TestNftNATPerNodeTables(t *testing.T) {
	f := &fakeNft{tables: map[string][]string{nftLegacyTable: {"ip saddr 100.64.0.0/10 ip daddr " + testLAN + " masquerade"}}}
	be := nftNAT{run: f.run}
	a, b := testNode(1), testNode(2)
	routes := []netip.Prefix{mustPfx(testLAN)}

	cleanupB, _, err := be.masquerade(b, routes)
	if err != nil {
		t.Fatal(err)
	}
	var cleanupA func()
	for range 3 {
		if cleanupA, _, err = be.masquerade(a, routes); err != nil { // killed each time
			t.Fatal(err)
		}
	}
	if _, ok := f.tables[nftLegacyTable]; ok {
		t.Error("the pre-owner shared table survived")
	}
	if got := f.tables[nftTableFor(a)]; len(got) != 1 {
		t.Errorf("A's table holds %d rules after unclean restarts, want 1: %q", len(got), got)
	}
	if got := f.tables[nftTableFor(b)]; len(got) != 1 {
		t.Errorf("A's starts disturbed B's table: %q", got)
	}
	cleanupA()
	if _, ok := f.tables[nftTableFor(b)]; !ok {
		t.Error("A stopping deleted B's table")
	}
	cleanupB()
	if len(f.tables) != 0 {
		t.Errorf("tables left after both stopped: %v", f.tables)
	}
}
