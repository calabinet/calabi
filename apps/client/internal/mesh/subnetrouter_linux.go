//go:build linux && !android

package mesh

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"time"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// How long ONE iptables invocation may take. These exist because the -w below
// waits for the xtables lock without a deadline of its own on the iptables
// versions we must support; these are that deadline.
const (
	// iptablesTimeout applies to installing and removing real rules. Generous:
	// nobody is waiting on it, and giving up early leaves the node advertising a
	// route it does not rewrite.
	iptablesTimeout = 10 * time.Second
	// iptablesProbeTimeout applies to the capability probe, which runs inside a
	// console request. Three shell-outs at the rule timeout would make a
	// contended machine look like a hung page, and the probe has somewhere good
	// to fall back to that rule installation does not: it can answer "unknown".
	iptablesProbeTimeout = 3 * time.Second
)

// runIptables runs one iptables command with the xtables lock WAIT enabled.
//
// -w is not optional, and its absence was a live bug. Without it iptables exits
// 4 the instant another process holds the lock, and that other process is
// routinely THIS daemon: a route change restarts the mesh session, which
// reinstalls the MASQUERADE and NETMAP rules, while the console refetches
// /v1/mesh/advertise and probes for the NETMAP capability. That is how a machine
// carrying a live `-j NETMAP` rule came to be told it could not install one
// (field report 2026-09-09), and the same race could equally have failed the
// real rule installation, which is a silent black hole rather than a wrong
// label.
//
// Bare -w, never `-w <seconds>`: the seconds argument needs iptables 1.6 (2016)
// and is a parse error on the 1.4.21 that RHEL 7 and Debian 8 ship. The
// unbounded wait that leaves is bounded by ctx instead.
func runIptables(args ...string) ([]byte, error) {
	return runIptablesWithin(iptablesTimeout, args...)
}

func runIptablesWithin(d time.Duration, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return exec.CommandContext(ctx, "iptables", append([]string{"-w"}, args...)...).CombinedOutput()
}

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
// node is this node's key and names the rules as its own (see natOwner): any
// that an earlier run of the same node failed to remove are deleted first, so a
// start after an unclean exit replaces the rules instead of adding a copy.
//
// NAT backend: prefers `iptables` (which on modern systems is the iptables-nft
// shim, so it programs nftables anyway), and falls back to native `nft` when the
// iptables binary is absent. If NEITHER is installed it returns a clear error so
// the daemon can warn the operator — advertising still happens, but this node
// won't forward until a backend exists.
func EnableSubnetRouter(node meshproto.NodeKey, routes []netip.Prefix, logger *slog.Logger) (func(), error) {
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
	cleanup, reclaimed, err := be.masquerade(node, routes)
	logReclaimedNAT(logger, "masquerade", reclaimed)
	return cleanup, err
}

// EnableSubnetAliases installs the rewrite from each published alias prefix to
// the real subnet behind this node, and returns a cleanup that removes them.
// Like EnableSubnetRouter it first removes whatever an earlier run of this node
// left in place.
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
func EnableSubnetAliases(node meshproto.NodeKey, aliases []SubnetAlias, logger *slog.Logger) (func(), error) {
	if len(aliases) == 0 {
		return func() {}, nil
	}
	be, err := pickNATBackend()
	if err != nil {
		return nil, err
	}
	cleanup, reclaimed, err := be.aliasRewrite(node, aliases)
	logReclaimedNAT(logger, "alias rewrite", reclaimed)
	return cleanup, err
}

// logReclaimedNAT says when a start had to clear rules an earlier run left. It
// is the only trace of that run having exited without cleaning up, and it
// explains a slow first start on a host that had piled up many copies.
func logReclaimedNAT(logger *slog.Logger, kind string, n int) {
	if n > 0 && logger != nil {
		logger.Info("mesh: removed NAT rules an earlier run of this node left behind", "kind", kind, "removed", n)
	}
}

func ipForwardEnabled() bool {
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	return err == nil && strings.TrimSpace(string(b)) == "1"
}

// natBackend applies the overlay MASQUERADE rules for a set of advertised routes,
// and the 1:1 rewrite rules for any of them published under an alias. Both
// report how many leftover rules of this node's they removed first.
type natBackend interface {
	masquerade(node meshproto.NodeKey, routes []netip.Prefix) (func(), int, error)
	aliasRewrite(node meshproto.NodeKey, aliases []SubnetAlias) (func(), int, error)
}

// pickNATBackend selects a NAT implementation: iptables if present (works via
// legacy or the nft-compat shim), else nft, else a clear "install one" error.
func pickNATBackend() (natBackend, error) {
	if _, err := exec.LookPath("iptables"); err == nil {
		return iptablesNAT{run: runIptables}, nil
	}
	if _, err := exec.LookPath("nft"); err == nil {
		return nftNAT{run: runNft}, nil
	}
	return nil, fmt.Errorf("subnet-router / exit-node forwarding needs a NAT backend, but neither `iptables` nor `nft` was found — install one (e.g. `apt install iptables` or `apt install nftables`) and restart the daemon")
}

func runNft(args ...string) ([]byte, error) {
	return exec.Command("nft", args...).CombinedOutput()
}

// probeSubnetAlias answers "can this host install the 1:1 alias rewrite" by
// TRYING it, in a chain of our own that nothing jumps to. It is a property of
// the machine, not a preference: aliasing is applied to every published route,
// so there is nothing for an operator to choose.
//
// The cheaper tests are all wrong. `iptables` being on PATH says nothing about
// the xt_NETMAP module, which is packaged separately on several distributions
// and autoloads only when a rule references it; parsing `iptables -m netmap -h`
// or /proc/modules guesses at the answer the kernel will give. Guessing here
// costs a silently unreachable subnet: the coordinator hands out the alias, the
// rule fails to install, and peers route to an address that goes nowhere.
//
// It returns a TRI-STATE. The bool it replaced could not distinguish "the
// kernel refused" from "iptables could not run just now", and reported both as
// "unsupported" — see aliassupport.go for what that cost. Callers should reach
// this through SubnetAliasSupport, which prefers an observed install over a
// probe and caches the verdict.
//
// The probe chain is never hooked into PREROUTING, and both addresses are
// RFC 5737 documentation space, so a leftover chain from a killed daemon
// forwards nothing.
func probeSubnetAlias() (AliasSupport, string) {
	be, err := pickNATBackend()
	if err != nil {
		return AliasSupportNo, err.Error()
	}
	ipt, ok := be.(iptablesNAT)
	if !ok {
		return AliasSupportNo, "only the `nft` backend is available; the 1:1 rewrite needs `iptables` with the NETMAP target"
	}
	return ipt.netmapUsable()
}

// aliasProbeChain is a nat-table chain with no jump into it: creating and
// filling it exercises the NETMAP target without touching packet flow.
//
// One fixed name, not one per process: a name carrying a pid would leak a chain
// every time a daemon was killed mid-probe, with nothing left to recognise it
// by. Two probes racing over the shared name is handled a level up instead —
// SubnetAliasSupport holds a mutex across the whole probe — which also stops one
// probe's cleanup from deleting the chain another is still filling.
const aliasProbeChain = "CALABI-ALIAS-PROBE"

func (iptablesNAT) netmapUsable() (AliasSupport, string) {
	if _, err := runIptablesWithin(iptablesProbeTimeout, "-t", "nat", "-N", aliasProbeChain); err != nil {
		// Most likely left behind by a daemon that was killed mid-probe. Reuse it
		// if we can empty it; if even that fails, we have no working iptables.
		if fout, ferr := runIptablesWithin(iptablesProbeTimeout, "-t", "nat", "-F", aliasProbeChain); ferr != nil {
			return aliasProbeVerdict("create or reuse the probe chain", fout, ferr)
		}
	}
	defer func() {
		_, _ = runIptablesWithin(iptablesProbeTimeout, "-t", "nat", "-F", aliasProbeChain)
		_, _ = runIptablesWithin(iptablesProbeTimeout, "-t", "nat", "-X", aliasProbeChain)
	}()
	if out, err := runIptablesWithin(iptablesProbeTimeout, "-t", "nat", "-A", aliasProbeChain,
		"-d", "192.0.2.0/32", "-j", "NETMAP", "--to", "198.51.100.0/32"); err != nil {
		return aliasProbeVerdict("install a NETMAP rule", out, err)
	}
	return AliasSupportYes, "a NETMAP rule installed cleanly in a probe chain"
}
