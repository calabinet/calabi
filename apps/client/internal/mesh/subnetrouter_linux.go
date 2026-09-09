//go:build linux

package mesh

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
)

// SubnetRouterSupported reports whether this build can actually forward for the
// routes it advertises. It lives beside each backend rather than as a
// `runtime.GOOS == "linux"` test at the call sites so it cannot drift from the
// implementation it describes: the day a second platform grows an
// EnableSubnetRouter, this file's neighbour flips with it.
func SubnetRouterSupported() bool { return true }

// EnableSubnetRouter turns this node into a subnet router for the given CIDRs:
// it enables IPv4 forwarding and MASQUERADEs mesh traffic (from the overlay
// range) destined for each advertised CIDR, so a LAN host's replies return via
// this node without the LAN needing a route back to the overlay. A 0.0.0.0/0
// route is an exit node (MASQUERADE everything leaving the mesh). Returns a
// cleanup that removes the NAT rules. Needs CAP_NET_ADMIN.
//
// NAT backend: prefers `iptables` (which on modern systems is the iptables-nft
// shim, so it programs nftables anyway), and falls back to native `nft` when the
// iptables binary is absent. If NEITHER is installed it returns a clear error so
// the daemon can warn the operator — advertising still happens, but this node
// won't forward until a backend exists.
func EnableSubnetRouter(routes []netip.Prefix) (func(), error) {
	if len(routes) == 0 {
		return func() {}, nil
	}
	// Enable IPv4 forwarding — but only write if it isn't already on. In a
	// container /proc/sys is often read-only yet ip_forward is already 1
	// (Docker/host default), so a failed write there is fine.
	if !ipForwardEnabled() {
		if out, err := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").CombinedOutput(); err != nil {
			return nil, fmt.Errorf("enable ip_forward: %v: %s", err, strings.TrimSpace(string(out)))
		}
	}
	be, err := pickNATBackend()
	if err != nil {
		return nil, err
	}
	return be.masquerade(routes)
}

// EnableSubnetAliases installs the rewrite from each published alias prefix to
// the real subnet behind this node, and returns a cleanup that removes them.
//
// Separate from EnableSubnetRouter because the two learn their inputs at
// different times: the routes come from this machine's own config and are known
// at session start, while the aliases are ASSIGNED by the coordinator and arrive
// with the netmap. Folding them together would mean deferring forwarding until
// the first netmap, which would make a plain subnet router wait on the control
// plane for something it never needed.
//
// Forwarding itself (ip_forward + MASQUERADE) is EnableSubnetRouter's job and is
// assumed already done: an alias without it rewrites packets that then go
// nowhere.
func EnableSubnetAliases(aliases []SubnetAlias) (func(), error) {
	if len(aliases) == 0 {
		return func() {}, nil
	}
	be, err := pickNATBackend()
	if err != nil {
		return nil, err
	}
	return be.aliasRewrite(aliases)
}

func ipForwardEnabled() bool {
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	return err == nil && strings.TrimSpace(string(b)) == "1"
}

// natBackend applies the overlay MASQUERADE rules for a set of advertised routes,
// and the 1:1 rewrite rules for any of them published under an alias.
type natBackend interface {
	masquerade(routes []netip.Prefix) (func(), error)
	aliasRewrite(aliases []SubnetAlias) (func(), error)
}

// pickNATBackend selects a NAT implementation: iptables if present (works via
// legacy or the nft-compat shim), else nft, else a clear "install one" error.
func pickNATBackend() (natBackend, error) {
	if _, err := exec.LookPath("iptables"); err == nil {
		return iptablesNAT{}, nil
	}
	if _, err := exec.LookPath("nft"); err == nil {
		return nftNAT{}, nil
	}
	return nil, fmt.Errorf("subnet-router / exit-node forwarding needs a NAT backend, but neither `iptables` nor `nft` was found — install one (e.g. `apt install iptables` or `apt install nftables`) and restart the daemon")
}

// --- iptables backend -------------------------------------------------------

type iptablesNAT struct{}

func (iptablesNAT) masquerade(routes []netip.Prefix) (func(), error) {
	var added [][]string
	for _, rule := range iptablesMasqueradeRules(routes) {
		if out, err := exec.Command("iptables", rule...).CombinedOutput(); err != nil {
			cleanupIptablesRules(added)
			return nil, fmt.Errorf("iptables masquerade %v: %v: %s", rule, err, strings.TrimSpace(string(out)))
		}
		added = append(added, rule)
	}
	return func() { cleanupIptablesRules(added) }, nil
}

func (iptablesNAT) aliasRewrite(aliases []SubnetAlias) (func(), error) {
	var added [][]string
	for _, rule := range iptablesAliasRules(aliases) {
		if out, err := exec.Command("iptables", rule...).CombinedOutput(); err != nil {
			cleanupIptablesRules(added)
			return nil, fmt.Errorf("iptables alias rewrite %v: %v: %s (the NETMAP target needs the xt_NETMAP module)",
				rule, err, strings.TrimSpace(string(out)))
		}
		added = append(added, rule)
	}
	return func() { cleanupIptablesRules(added) }, nil
}

func cleanupIptablesRules(rules [][]string) {
	for _, rule := range rules {
		del := append([]string(nil), rule...)
		del[2] = "-D" // -A -> -D
		_ = exec.Command("iptables", del...).Run()
	}
}

// --- nftables backend -------------------------------------------------------

// nftTable is a dedicated table so cleanup is a single atomic `delete table`
// that can't touch the operator's own rules.
const nftTable = "calabi_mesh"

type nftNAT struct{}

func (nftNAT) masquerade(routes []netip.Prefix) (func(), error) {
	rules := nftMasqueradeRules(routes)
	if len(rules) == 0 {
		return func() {}, nil
	}
	// Fresh table each session: delete any leftover (ignore error), then create.
	_ = exec.Command("nft", "delete", "table", "ip", nftTable).Run()
	setup := [][]string{
		{"add", "table", "ip", nftTable},
		{"add", "chain", "ip", nftTable, "postrouting", "{", "type", "nat", "hook", "postrouting", "priority", "100", ";", "}"},
	}
	for _, r := range rules {
		setup = append(setup, append([]string{"add", "rule", "ip", nftTable, "postrouting"}, strings.Fields(r)...))
	}
	for _, args := range setup {
		if out, err := exec.Command("nft", args...).CombinedOutput(); err != nil {
			_ = exec.Command("nft", "delete", "table", "ip", nftTable).Run()
			return nil, fmt.Errorf("nft %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
	}
	return func() { _ = exec.Command("nft", "delete", "table", "ip", nftTable).Run() }, nil
}

// aliasRewrite is not implemented on the nft backend. A 1:1 block rewrite is
// what iptables spells NETMAP; nft expresses it differently and the translation
// is not one this has been tested against, so it says so rather than installing
// rules that might mean something else. iptables is the preferred backend
// anyway (pickNATBackend tries it first, and on a modern system it is the
// nft-compat shim, which programs nftables regardless).
func (nftNAT) aliasRewrite(aliases []SubnetAlias) (func(), error) {
	if len(aliases) == 0 {
		return func() {}, nil
	}
	return nil, fmt.Errorf("subnet aliases need the `iptables` NAT backend (NETMAP target); this host has only `nft` — install iptables (e.g. `apt install iptables`) and restart the daemon")
}

// SubnetAliasSupported reports whether THIS host can actually install the 1:1
// alias rewrite. It is a property of the machine, not a preference: aliasing is
// applied to every published route, so there is nothing for an operator to
// choose — the only question is whether the kernel and userland can do it.
//
// It is answered by TRYING, in a chain of our own that nothing jumps to. The
// cheaper tests are all wrong: `iptables` being on PATH says nothing about the
// xt_NETMAP module, which is packaged separately on several distributions and
// autoloads only when a rule references it, and parsing `iptables -m netmap -h`
// or /proc/modules guesses at the answer the kernel will give. Guessing here
// costs a silently unreachable subnet: the coordinator hands out the alias, the
// rule fails to install, and peers route to an address that goes nowhere.
//
// The probe chain is never hooked into PREROUTING, and both addresses are
// RFC 5737 documentation space, so a leftover chain from a killed daemon
// forwards nothing.
func SubnetAliasSupported() bool {
	be, err := pickNATBackend()
	if err != nil {
		return false
	}
	ipt, ok := be.(iptablesNAT)
	if !ok {
		return false // the nft backend deliberately does not implement aliases
	}
	return ipt.netmapUsable()
}

// aliasProbeChain is a nat-table chain with no jump into it: creating and
// filling it exercises the NETMAP target without touching packet flow.
const aliasProbeChain = "CALABI-ALIAS-PROBE"

func (iptablesNAT) netmapUsable() bool {
	if err := exec.Command("iptables", "-t", "nat", "-N", aliasProbeChain).Run(); err != nil {
		// Most likely left behind by a daemon that was killed mid-probe. Reuse it
		// if we can empty it; if even that fails, we have no working iptables.
		if exec.Command("iptables", "-t", "nat", "-F", aliasProbeChain).Run() != nil {
			return false
		}
	}
	defer func() {
		_ = exec.Command("iptables", "-t", "nat", "-F", aliasProbeChain).Run()
		_ = exec.Command("iptables", "-t", "nat", "-X", aliasProbeChain).Run()
	}()
	err := exec.Command("iptables", "-t", "nat", "-A", aliasProbeChain,
		"-d", "192.0.2.0/32", "-j", "NETMAP", "--to", "198.51.100.0/32").Run()
	return err == nil
}
