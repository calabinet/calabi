//go:build linux

package mesh

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
)

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

func ipForwardEnabled() bool {
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	return err == nil && strings.TrimSpace(string(b)) == "1"
}

// natBackend applies the overlay MASQUERADE rules for a set of advertised routes.
type natBackend interface {
	masquerade(routes []netip.Prefix) (func(), error)
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
