//go:build darwin

package mesh

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

// enableExitRoutes makes this node a full-tunnel client of an exit node on macOS
// (the consumer side of MESH.7b). It mirrors the Linux path with the BSD `route`
// tool, the same wg-quick approach: pin coord + relay to the physical link FIRST
// (via the gateway `route -n get` reports for them now, before we hijack the
// default), then route 0.0.0.0/1 + 128.0.0.0/1 at the utun. Longest-prefix match
// makes the bypass /32s beat the tun /1s and the /1s beat the physical /0, so the
// default is overridden, not deleted. Returns a cleanup that removes exactly what
// it added (tun /1s first, so the box is never briefly unroutable). Needs root.
//
// The luid arg is Windows-only; ignored here. lanKeep are the private/local
// ranges to hold on the physical link (MESH.7b "allow LAN access") so
// full-tunnelling never cuts off the local network.
func enableExitRoutes(_ uint64, ifname string, bypass []netip.Addr, lanKeep []netip.Prefix) (func(), error) {
	var pinned []netip.Addr
	var carved []netip.Prefix
	var splits []netip.Prefix
	undo := func() {
		// Remove the tun /1s first so the physical default is restored before the
		// bypass /32s go — the box is never briefly without a route out.
		for _, s := range splits {
			_ = exec.Command("route", "-n", "delete", "-net", s.String(), "-interface", ifname).Run()
		}
		for _, a := range pinned {
			_ = exec.Command("route", "-n", "delete", "-host", a.String()).Run()
		}
		for _, c := range carved {
			_ = exec.Command("route", "-n", "delete", "-net", c.String()).Run()
		}
	}

	// Pin coord + relay to the physical path FIRST, before the split default can
	// swallow them (WireGuard's own transport must keep escaping the tun).
	for _, a := range bypass {
		out, err := exec.Command("route", "-n", "get", a.String()).CombinedOutput()
		if err != nil {
			undo()
			return nil, fmt.Errorf("route get %s: %w: %s", a, err, strings.TrimSpace(string(out)))
		}
		gw, iface := parseDarwinRouteGet(string(out))
		if err := darwinPinHost(a, gw, iface); err != nil {
			undo()
			return nil, err
		}
		pinned = append(pinned, a)
	}

	// Keep the private/local ranges on the physical link so full-tunnelling never
	// cuts off the LAN (directly-connected AND one hop via the gateway). Route each
	// block to its current physical nexthop; more-specific subnet-router routes at
	// the utun still win by longest-prefix. A block with no physical route is left
	// alone — never fail the exit over it.
	for _, blk := range lanKeep {
		out, err := exec.Command("route", "-n", "get", blk.Addr().String()).CombinedOutput()
		if err != nil {
			continue
		}
		gw, iface := parseDarwinRouteGet(string(out))
		args := []string{"-n", "add", "-net", blk.String()}
		if ip, perr := netip.ParseAddr(gw); perr == nil && ip.IsValid() {
			args = append(args, gw)
		} else if iface != "" {
			args = append(args, "-interface", iface)
		} else {
			continue
		}
		if out, err := exec.Command("route", args...).CombinedOutput(); err != nil &&
			!strings.Contains(strings.ToLower(string(out)), "exists") {
			undo()
			return nil, fmt.Errorf("keep LAN %s on physical: %w: %s", blk, err, strings.TrimSpace(string(out)))
		}
		carved = append(carved, blk)
	}

	for _, s := range splitDefaultV4 {
		out, err := exec.Command("route", "-n", "add", "-net", s.String(), "-interface", ifname).CombinedOutput()
		if err != nil && !strings.Contains(strings.ToLower(string(out)), "exists") {
			undo()
			return nil, fmt.Errorf("route add -net %s -interface %s: %w: %s", s, ifname, err, strings.TrimSpace(string(out)))
		}
		splits = append(splits, s)
	}
	return undo, nil
}

// darwinPinHost adds a host route for addr over the physical path: via gw when
// it parses as a real IP, else -interface iface for an on-link destination. If
// the route already exists it is forced onto our nexthop with `route change`, so
// a stale entry can't blackhole the WireGuard transport.
func darwinPinHost(addr netip.Addr, gw, iface string) error {
	args := []string{"-n", "add", "-host", addr.String()}
	if ip, err := netip.ParseAddr(gw); err == nil && ip.IsValid() {
		args = append(args, gw)
	} else if iface != "" {
		args = append(args, "-interface", iface)
	} else {
		return fmt.Errorf("no physical gateway/interface for bypass %s", addr)
	}

	out, err := exec.Command("route", args...).CombinedOutput()
	if err == nil {
		return nil
	}
	if strings.Contains(strings.ToLower(string(out)), "exists") {
		args[1] = "change"
		if out2, err2 := exec.Command("route", args...).CombinedOutput(); err2 != nil {
			return fmt.Errorf("route change -host %s: %w: %s", addr, err2, strings.TrimSpace(string(out2)))
		}
		return nil
	}
	return fmt.Errorf("route add -host %s: %w: %s", addr, err, strings.TrimSpace(string(out)))
}
