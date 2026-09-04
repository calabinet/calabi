//go:build linux

package mesh

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

// splitDefault is the classic pair of routes that override the physical default
// (0.0.0.0/0) by longest-prefix match WITHOUT replacing it: together they cover
// all of IPv4, so removing them cleanly restores the original default route.
var splitDefault = []string{"0.0.0.0/1", "128.0.0.0/1"}

// enableExitRoutes turns this node into a full-tunnel client of an exit node
// (MESH.7b). It first pins the control-plane endpoints (coord + relay) to the
// physical link — captured from the CURRENT route table before we hijack the
// default — so WireGuard's own transport keeps escaping; then it routes
// 0.0.0.0/1 + 128.0.0.0/1 at the tun so every other destination flows to the
// exit peer. Returns a cleanup that removes exactly what it added (bypass /32s
// last, so the box is never briefly unroutable). Needs CAP_NET_ADMIN.
//
// The luid arg is Windows-only (see exitroute_windows.go); ignored on Linux.
// lanKeep are the private/local ranges to hold on the physical link (MESH.7b
// "allow LAN access") so full-tunnelling never cuts off the local network.
func enableExitRoutes(_ uint64, ifname string, bypass []netip.Addr, lanKeep []netip.Prefix) (func(), error) {
	var pinned []netip.Addr
	var carved []netip.Prefix
	undo := func() {
		for _, s := range splitDefault {
			_ = exec.Command("ip", "route", "del", s, "dev", ifname).Run()
		}
		for _, a := range pinned {
			_ = exec.Command("ip", "route", "del", a.String()+"/32").Run()
		}
		for _, c := range carved {
			_ = exec.Command("ip", "route", "del", c.String()).Run()
		}
	}

	// Pin coord + relay to the physical path FIRST (before the split default can
	// swallow them). Skip any that already resolve on-link to the tun (none should).
	for _, a := range bypass {
		path, err := physicalRouteTo(a)
		if err != nil {
			undo()
			return nil, fmt.Errorf("resolve physical route to %s: %w", a, err)
		}
		args := append([]string{"route", "replace", a.String() + "/32"}, path...)
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			undo()
			return nil, fmt.Errorf("pin bypass %s: %v: %s", a, err, strings.TrimSpace(string(out)))
		}
		pinned = append(pinned, a)
	}

	// Keep the private/local ranges on the physical link so full-tunnelling never
	// cuts off the LAN (directly-connected AND one hop via the gateway). Route each
	// block to its current physical nexthop; more-specific subnet-router routes at
	// the tun still win by longest-prefix. A block already on the physical path, or
	// with no route at all, is left alone — never fail the exit over it.
	for _, blk := range lanKeep {
		path, err := physicalRouteTo(blk.Addr())
		if err != nil {
			continue
		}
		args := append([]string{"route", "add", blk.String()}, path...)
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			if strings.Contains(strings.ToLower(string(out)), "exists") {
				continue
			}
			undo()
			return nil, fmt.Errorf("keep LAN %s on physical: %v: %s", blk, err, strings.TrimSpace(string(out)))
		}
		carved = append(carved, blk)
	}

	for _, s := range splitDefault {
		if out, err := exec.Command("ip", "route", "add", s, "dev", ifname).CombinedOutput(); err != nil &&
			!strings.Contains(strings.ToLower(string(out)), "exists") {
			undo()
			return nil, fmt.Errorf("route %s dev %s: %v: %s", s, ifname, err, strings.TrimSpace(string(out)))
		}
	}
	return undo, nil
}

// physicalRouteTo returns the `ip route` nexthop args (`via GW dev IF` or just
// `dev IF` for on-link) the kernel uses to reach addr RIGHT NOW — i.e. over the
// physical link, since this is called before the split-default routes exist.
func physicalRouteTo(addr netip.Addr) ([]string, error) {
	out, err := exec.Command("ip", "route", "get", addr.String()).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	// e.g. "8.8.8.8 via 172.20.0.1 dev eth0 src ..." or "172.20.0.6 dev eth0 src ..."
	f := strings.Fields(string(out))
	var gw, dev string
	for i := 0; i < len(f)-1; i++ {
		switch f[i] {
		case "via":
			gw = f[i+1]
		case "dev":
			dev = f[i+1]
		}
	}
	if dev == "" {
		return nil, fmt.Errorf("no device in %q", strings.TrimSpace(string(out)))
	}
	if gw != "" {
		return []string{"via", gw, "dev", dev}, nil
	}
	return []string{"dev", dev}, nil
}
