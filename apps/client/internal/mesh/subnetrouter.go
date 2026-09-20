package mesh

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

// The subnet-router / exit-node NAT rule builders, and the install/reclaim logic
// that applies them, live here (no build tag) so they can be unit-tested on any
// OS against a model of the nat table; the Linux backend (subnetrouter_linux.go)
// only supplies the real iptables / nft invocations. The rules MASQUERADE
// overlay-sourced traffic (meshOverlayCIDR) heading to an advertised CIDR — or,
// for a 0.0.0.0/0 exit node, to anywhere outside the overlay — so LAN / internet
// replies return via this node without the far side needing a route back to the
// overlay.

// natOwner names the NAT rules one mesh node installs on this host.
//
// WHY RULES CARRY AN OWNER. Installing used to be a bare `iptables -A`, and
// removing them a cleanup that ran only if the process lived to run it. A daemon
// that did not — killed by systemd, crashed, or (until 2026-09-17) ANY platform
// daemon stopped normally, which exited without waiting for its mesh session to
// tear down — left its copy behind, and the next start appended another. Field
// report 2026-09-17: a Rocky subnet router with ~40 identical
// `-s 100.64.0.0/10 -d 192.168.1.0/24 -j MASQUERADE` lines in POSTROUTING. So a
// start now first removes what an earlier run left, and that needs a way to
// tell "left by an earlier run of this node" from everything else in the table.
//
// The node key, not the process: the rules must be recognisable to the NEXT
// process, and two clients on one machine (--service-name, each with its own
// data dir and so its own key) must not reclaim each other's. Two daemons that
// advertise the same subnet therefore hold one copy each, and either can stop
// without taking the other's forwarding with it.
//
// Lower-case hex on purpose: iptables quotes a comment in its -S output as soon
// as it holds anything outside [A-Za-z0-9_-], and reclaim reads that output.
func natOwner(node meshproto.NodeKey) string { return hex.EncodeToString(node[:8]) }

// iptablesOwnerComment is the `-m comment` text marking a rule as this node's.
func iptablesOwnerComment(node meshproto.NodeKey) string { return "calabi-mesh-" + natOwner(node) }

// nftTableFor is this node's own nft table. 28 characters, inside the 32 that
// older kernels allow a table name.
func nftTableFor(node meshproto.NodeKey) string { return "calabi_mesh_" + natOwner(node) }

// nftLegacyTable is the one table every node shared before tables had owners.
// Those releases deleted it at every start whoever had created it, so removing
// it here takes nothing from anyone that they did not already lose.
const nftLegacyTable = "calabi_mesh"

// iptRule is one nat-table rule without its verb, so that appending it and
// deleting it are spelled from the same words.
type iptRule struct {
	chain  string   // POSTROUTING / PREROUTING
	match  []string // e.g. -s 100.64.0.0/10 -d 192.168.1.0/24
	target []string // e.g. -j MASQUERADE
}

// args spells the rule for one iptables invocation. A non-empty comment tags it
// with its owner; "" is the untagged form every release before owners installed.
func (r iptRule) args(verb, comment string) []string {
	a := append([]string{"-t", "nat", verb, r.chain}, r.match...)
	if comment != "" {
		a = append(a, "-m", "comment", "--comment", comment)
	}
	return append(a, r.target...)
}

// iptablesMasqueradeRules returns one MASQUERADE rule per IPv4 route.
func iptablesMasqueradeRules(routes []netip.Prefix) []iptRule {
	var rules []iptRule
	for _, r := range routes {
		if !r.Addr().Is4() {
			continue // v0: IPv4 subnet routes only
		}
		if r.Bits() == 0 { // exit node (default route)
			rules = append(rules, iptRule{"POSTROUTING", []string{"-s", meshOverlayCIDR, "!", "-d", meshOverlayCIDR}, []string{"-j", "MASQUERADE"}})
		} else {
			rules = append(rules, iptRule{"POSTROUTING", []string{"-s", meshOverlayCIDR, "-d", r.String()}, []string{"-j", "MASQUERADE"}})
		}
	}
	return rules
}

// nftMasqueradeRules returns the nft rule bodies (the text after
// `add rule ip <table> postrouting`) for each IPv4 route.
func nftMasqueradeRules(routes []netip.Prefix) []string {
	var rules []string
	for _, r := range routes {
		if !r.Addr().Is4() {
			continue
		}
		if r.Bits() == 0 { // exit node
			rules = append(rules, fmt.Sprintf("ip saddr %s ip daddr != %s masquerade", meshOverlayCIDR, meshOverlayCIDR))
		} else {
			rules = append(rules, fmt.Sprintf("ip saddr %s ip daddr %s masquerade", meshOverlayCIDR, r.String()))
		}
	}
	return rules
}

// iptablesAliasRules returns the rules that rewrite each alias prefix to its
// real one on the way IN — the other half of what makes an aliased subnet
// reachable, the MASQUERADE rules above being the way back out.
//
//	iptables -t nat -A PREROUTING -d 100.96.5.0/24 -j NETMAP --to 192.168.1.0/24
//
// NETMAP is a 1:1 block rewrite: it maps the network part and leaves the host
// part alone, which is exactly the alias contract (alias.222 is real.222) and
// is why no state or lookup table is involved. The reply direction needs no rule
// of its own — conntrack reverses this automatically, so the consumer sees the
// answer coming from the alias it dialled.
//
// Ordering with the MASQUERADE rules matters and is free: PREROUTING runs before
// the routing decision, so by the time POSTROUTING sees the packet its
// destination is already the real LAN address and the existing
// `-s 100.64/10 -d <real cidr>` rule matches unchanged.
func iptablesAliasRules(aliases []SubnetAlias) []iptRule {
	var rules []iptRule
	for _, a := range aliases {
		if !a.Alias.Addr().Is4() || !a.Real.Addr().Is4() || a.Alias.Bits() != a.Real.Bits() {
			continue // v0: IPv4, same size — anything else is not a 1:1 rewrite
		}
		rules = append(rules, iptRule{
			"PREROUTING",
			[]string{"-d", a.Alias.Masked().String()},
			[]string{"-j", "NETMAP", "--to", a.Real.Masked().String()},
		})
	}
	return rules
}

// --- iptables backend -------------------------------------------------------

// iptablesRunner runs one iptables invocation: args are everything after the
// binary name. Production is runIptables (xtables lock wait + deadline).
type iptablesRunner func(args ...string) ([]byte, error)

type iptablesNAT struct{ run iptablesRunner }

// iptablesError is a rule iptables refused, spelled the way the error messages
// have always named it.
type iptablesError struct {
	args []string
	out  []byte
	err  error
}

func (e *iptablesError) Error() string {
	return fmt.Sprintf("%v: %v: %s", e.args, e.err, strings.TrimSpace(string(e.out)))
}

func (e *iptablesError) Unwrap() error { return e.err }

// maxRuleCopies bounds each delete-until-gone loop. Far above anything a real
// host accumulates (one copy per unclean exit); it exists so an iptables that
// reported success without deleting could not spin a start forever.
const maxRuleCopies = 10000

func (b iptablesNAT) masquerade(node meshproto.NodeKey, routes []netip.Prefix) (func(), int, error) {
	cleanup, reclaimed, err := b.install(node, "POSTROUTING", iptablesMasqueradeRules(routes))
	if err != nil {
		return nil, reclaimed, fmt.Errorf("iptables masquerade %w", err)
	}
	return cleanup, reclaimed, nil
}

func (b iptablesNAT) aliasRewrite(node meshproto.NodeKey, aliases []SubnetAlias) (func(), int, error) {
	cleanup, reclaimed, err := b.install(node, "PREROUTING", iptablesAliasRules(aliases))
	if err != nil {
		return nil, reclaimed, fmt.Errorf("iptables alias rewrite %w (the NETMAP target needs the xt_NETMAP module)", err)
	}
	return cleanup, reclaimed, nil
}

// install replaces whatever this node already has in chain with rules, and
// returns a cleanup that removes exactly what it added plus the number of
// leftover rules it deleted first.
//
// ONE CHAIN, ONE INSTALLER. The reclaim step removes every rule in chain that
// carries this node's comment, not just copies of the rules being installed: a
// route withdrawn, or an alias reassigned, while the daemon was down leaves a
// rule nothing would otherwise match again. That is only safe because each chain
// is written by exactly one caller — MASQUERADE in POSTROUTING, the alias
// rewrite in PREROUTING — and the two have different lifetimes (the data plane's
// and a control-plane session's). A third kind of rule needs a chain of its own
// or a comment of its own.
//
// Untagged copies of the SAME rules are removed too. Those are what releases
// before owner comments left behind, and nothing can tell whose they were; but
// those releases' own cleanup deleted the first exact match it found, whoever
// had added it, so taking them away here is no less than already happened on
// every graceful stop — and the tagged copy that replaces them does the same
// job.
//
// A host whose iptables cannot load the comment match gets the untagged rule
// rather than no forwarding. It still does not accumulate — the untagged sweep
// above removes an earlier run's copy — and what it gives up is only telling two
// clients on that one machine apart.
func (b iptablesNAT) install(node meshproto.NodeKey, chain string, rules []iptRule) (func(), int, error) {
	if len(rules) == 0 {
		return func() {}, 0, nil
	}
	comment := iptablesOwnerComment(node)
	reclaimed := b.deleteTagged(chain, comment)

	type placed struct {
		rule    iptRule
		comment string
	}
	var added []placed
	undo := func() {
		for i := len(added) - 1; i >= 0; i-- {
			_, _ = b.run(added[i].rule.args("-D", added[i].comment)...)
		}
	}
	for _, r := range rules {
		reclaimed += b.deleteCopies(r, "")
		if _, err := b.run(r.args("-A", comment)...); err == nil {
			added = append(added, placed{r, comment})
			continue
		}
		if out, err := b.run(r.args("-A", "")...); err != nil {
			undo()
			return nil, reclaimed, &iptablesError{args: r.args("-A", ""), out: out, err: err}
		}
		added = append(added, placed{r, ""})
	}
	return undo, reclaimed, nil
}

// deleteCopies deletes every copy of one exact rule and reports how many there
// were. Each -D removes the first match; the loop ends at the first refusal,
// which is "no such rule" once they are gone.
func (b iptablesNAT) deleteCopies(r iptRule, comment string) int {
	n := 0
	for n < maxRuleCopies {
		if _, err := b.run(r.args("-D", comment)...); err != nil {
			break
		}
		n++
	}
	return n
}

// deleteTagged deletes every rule in chain carrying comment, whatever it
// matches, and reports how many. It works from `-S`, whose lines are the -A
// spelling of each rule, so turning one into its -D is a one-word change.
// Failing to list is not an error worth failing the install over: the only
// cost is stale rules staying where they already were.
func (b iptablesNAT) deleteTagged(chain, comment string) int {
	out, err := b.run("-t", "nat", "-S", chain)
	if err != nil {
		return 0
	}
	n := 0
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "-A" || f[1] != chain || !hasCommentField(f, comment) {
			continue
		}
		del := append([]string{"-t", "nat", "-D"}, f[1:]...)
		if _, err := b.run(del...); err == nil {
			n++
		}
	}
	return n
}

// hasCommentField reports whether a -S line carries exactly this comment. Our
// comments never need quoting (see natOwner), so the field is the bare text.
func hasCommentField(fields []string, comment string) bool {
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "--comment" && fields[i+1] == comment {
			return true
		}
	}
	return false
}

// --- nftables backend -------------------------------------------------------

// nftRunner runs one nft invocation: args are everything after the binary name.
type nftRunner func(args ...string) ([]byte, error)

// nftNAT keeps each node's rules in a table of its own, so cleanup is a single
// atomic `delete table` that can touch neither the operator's rules nor another
// client's on the same machine.
type nftNAT struct{ run nftRunner }

func (b nftNAT) masquerade(node meshproto.NodeKey, routes []netip.Prefix) (func(), int, error) {
	rules := nftMasqueradeRules(routes)
	if len(rules) == 0 {
		return func() {}, 0, nil
	}
	table := nftTableFor(node)
	// Fresh table each session: delete this node's leftover and the pre-owner
	// shared one (an error just means there was none), then create.
	reclaimed := 0
	for _, t := range []string{table, nftLegacyTable} {
		if _, err := b.run("delete", "table", "ip", t); err == nil {
			reclaimed++
		}
	}
	setup := [][]string{
		{"add", "table", "ip", table},
		{"add", "chain", "ip", table, "postrouting", "{", "type", "nat", "hook", "postrouting", "priority", "100", ";", "}"},
	}
	for _, r := range rules {
		setup = append(setup, append([]string{"add", "rule", "ip", table, "postrouting"}, strings.Fields(r)...))
	}
	for _, args := range setup {
		if out, err := b.run(args...); err != nil {
			_, _ = b.run("delete", "table", "ip", table)
			return nil, reclaimed, fmt.Errorf("nft %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
	}
	return func() { _, _ = b.run("delete", "table", "ip", table) }, reclaimed, nil
}

// aliasRewrite is not implemented on the nft backend. A 1:1 block rewrite is
// what iptables spells NETMAP; nft expresses it differently and the translation
// is not one this has been tested against, so it says so rather than installing
// rules that might mean something else. iptables is the preferred backend
// anyway (pickNATBackend tries it first, and on a modern system it is the
// nft-compat shim, which programs nftables regardless).
func (nftNAT) aliasRewrite(_ meshproto.NodeKey, aliases []SubnetAlias) (func(), int, error) {
	if len(aliases) == 0 {
		return func() {}, 0, nil
	}
	return nil, 0, fmt.Errorf("subnet aliases need the `iptables` NAT backend (NETMAP target); this host has only `nft` — install iptables (e.g. `apt install iptables`) and restart the daemon")
}
