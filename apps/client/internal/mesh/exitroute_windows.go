//go:build windows

package mesh

import (
	"fmt"
	"net/netip"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// enableExitRoutes makes this node a full-tunnel client of an exit node on
// Windows (the consumer side of MESH.7b). It mirrors the Linux path via the IP
// Helper API (winipcfg), the same mechanism WireGuard's own Windows client uses:
// pin the control-plane endpoints (coord + relay) to the physical link FIRST —
// via the gateway the OS uses for them right now, captured before we hijack the
// default — then route 0.0.0.0/1 + 128.0.0.0/1 at the tun so every other
// destination flows to the exit peer. Longest-prefix match makes the bypass /32s
// beat the tun /1s and the /1s beat the physical /0, so the physical default is
// overridden, never deleted. Returns a cleanup that removes exactly what it added
// (tun /1s first, so the box is never briefly unroutable). Needs administrator.
//
// luid is the wintun adapter LUID (WGDatapath.tunLUID); ifname is error context.
// lanKeep are the private/local ranges to hold on the physical link (MESH.7b
// "allow LAN access") so full-tunnelling never cuts off the local network.
func enableExitRoutes(luid uint64, ifname string, bypass []netip.Addr, lanKeep []netip.Prefix) (func(), error) {
	if luid == 0 {
		return nil, fmt.Errorf("mesh: tun %q has no wintun LUID; cannot take exit-node default route", ifname)
	}
	tun := winipcfg.LUID(luid)

	type pin struct {
		l   winipcfg.LUID
		dst netip.Prefix
		gw  netip.Addr
	}
	var pins []pin
	var splits []netip.Prefix
	undo := func() {
		// Remove the tun /1s first so the physical default is restored before we
		// drop the bypass /32s — the box is never briefly without a route out.
		for _, s := range splits {
			_ = tun.DeleteRoute(s, onLinkNextHop(s.Addr()))
		}
		for _, p := range pins {
			_ = p.l.DeleteRoute(p.dst, p.gw)
		}
	}

	// Pin coord + relay to the physical path FIRST, before the split default can
	// swallow them (WireGuard's own transport must keep escaping the tun).
	for _, a := range bypass {
		gw, ifLUID, err := physicalNextHop(a, tun)
		if err != nil {
			undo()
			return nil, fmt.Errorf("resolve physical route to %s: %w", a, err)
		}
		dst := netip.PrefixFrom(a, a.BitLen()) // /32 or /128
		if err := ifLUID.AddRoute(dst, gw, 0); err != nil && !routeAlreadyExists(err) {
			undo()
			return nil, fmt.Errorf("pin bypass %s via %s: %w", a, gw, err)
		}
		pins = append(pins, pin{l: ifLUID, dst: dst, gw: gw})
	}

	// Keep the private/local ranges on the physical link so full-tunnelling never
	// cuts off the LAN. Resolve each block's CURRENT physical nexthop (before the
	// split default exists) and pin the whole block there; longest-prefix match
	// then keeps directly-connected /24s on-link and lets more-specific
	// subnet-router routes still win into the tun. A block with no physical route
	// (no gateway) is simply not carved — never fail the exit over it.
	for _, blk := range lanKeep {
		gw, ifLUID, err := physicalNextHop(blk.Addr(), tun)
		if err != nil {
			continue
		}
		if err := ifLUID.AddRoute(blk, gw, 0); err != nil && !routeAlreadyExists(err) {
			undo()
			return nil, fmt.Errorf("keep LAN %s on physical via %s: %w", blk, gw, err)
		}
		pins = append(pins, pin{l: ifLUID, dst: blk, gw: gw})
	}

	for _, s := range splitDefaultV4 {
		if err := addWinRoute(tun, s); err != nil {
			undo()
			return nil, err
		}
		splits = append(splits, s)
	}
	return undo, nil
}

// physicalNextHop returns the gateway + interface LUID the OS uses to reach dst
// RIGHT NOW over the physical link, skipping any route on the exclude interface
// (our tun) so we never pin a bypass back through the tunnel we're about to
// hijack. Called BEFORE the split-default routes exist, so the winning route is
// the physical one. Selection (longest prefix, then lowest metric) is done by the
// cross-platform pickPhysicalRoute so it stays unit-testable off Windows.
func physicalNextHop(dst netip.Addr, exclude winipcfg.LUID) (netip.Addr, winipcfg.LUID, error) {
	fam := winipcfg.AddressFamily(windows.AF_INET)
	if dst.Is6() {
		fam = winipcfg.AddressFamily(windows.AF_INET6)
	}
	tbl, err := winipcfg.GetIPForwardTable2(fam)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("read route table: %w", err)
	}
	rows := make([]routeEntry, 0, len(tbl))
	for i := range tbl {
		rows = append(rows, routeEntry{
			Prefix:  tbl[i].DestinationPrefix.Prefix(),
			Metric:  tbl[i].Metric,
			NextHop: tbl[i].NextHop.Addr(),
			LUID:    uint64(tbl[i].InterfaceLUID),
		})
	}
	best, ok := pickPhysicalRoute(dst, rows, uint64(exclude))
	if !ok {
		return netip.Addr{}, 0, fmt.Errorf("no physical route to %s", dst)
	}
	return best.NextHop, winipcfg.LUID(best.LUID), nil
}

// onLinkNextHop is the unspecified next hop for a route added on-link (no
// gateway) at an interface — the family-correct zero address addWinRoute uses,
// recomputed here so DeleteRoute matches the entry we added.
func onLinkNextHop(a netip.Addr) netip.Addr {
	if a.Is6() {
		return netip.IPv6Unspecified()
	}
	return netip.IPv4Unspecified()
}
