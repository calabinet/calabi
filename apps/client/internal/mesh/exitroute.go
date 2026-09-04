package mesh

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// splitDefaultV4 is the classic pair of routes that override the physical
// default (0.0.0.0/0) by longest-prefix match WITHOUT replacing it: together
// they cover all of IPv4, so removing them cleanly restores the original
// default. Shared by the Windows/macOS exit-route paths; the Linux path keeps
// its own string form. v0 hijacks IPv4 only — IPv6 keeps flowing over the
// physical link, matching the Linux behaviour.
var splitDefaultV4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/1"),
	netip.MustParsePrefix("128.0.0.0/1"),
}

// routeEntry is one OS routing-table row reduced to the fields exit-route
// selection needs; the platform layer fills it from the native route table.
type routeEntry struct {
	Prefix  netip.Prefix
	Metric  uint32
	NextHop netip.Addr
	LUID    uint64 // opaque interface id (the wintun/physical adapter LUID on Windows)
}

// pickPhysicalRoute selects the best route to dst — longest prefix, then lowest
// metric — skipping any row on excludeLUID (our tun). It reproduces the kernel's
// best-route choice so the coord/relay bypass /32s get pinned to the real
// physical nexthop, never back into the tunnel we're about to hijack. This is the
// cross-platform core of the Windows bypass pin (see exitroute_windows.go);
// factored out here so the selection logic is unit-testable on any OS.
// ok=false means dst has no route off the tun.
func pickPhysicalRoute(dst netip.Addr, rows []routeEntry, excludeLUID uint64) (routeEntry, bool) {
	best := routeEntry{}
	bestLen := -1
	for _, r := range rows {
		if r.LUID == excludeLUID {
			continue
		}
		if !r.Prefix.IsValid() || !r.Prefix.Contains(dst) {
			continue
		}
		pl := r.Prefix.Bits()
		if pl > bestLen || (pl == bestLen && r.Metric < best.Metric) {
			best, bestLen = r, pl
		}
	}
	return best, bestLen >= 0
}

// parseDarwinRouteGet extracts the gateway + interface from `route -n get <dst>`
// output. On-link destinations report no numeric gateway (just an interface, or a
// link# token); callers use the interface in that case. Pure so the macOS
// exit-route path stays unit-testable off darwin (see exitroute_darwin.go).
func parseDarwinRouteGet(out string) (gw, iface string) {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "gateway:":
			gw = f[1]
		case "interface:":
			iface = f[1]
		}
	}
	return gw, iface
}

// resolveBypass turns the control-plane endpoints (coord + relay, given as
// host:port or bare host) into the concrete IPs that must keep flowing over the
// physical link while an exit node holds the default route. Every host must
// resolve: full-tunnelling with an unresolved relay/coord would blackhole the
// WireGuard transport itself (it would match the tun default route and loop), so
// an unresolvable endpoint is an error, not a skip.
func resolveBypass(hosts []string) ([]netip.Addr, error) {
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, h := range hosts {
		host := h
		if hp, _, err := net.SplitHostPort(h); err == nil {
			host = hp
		}
		if host == "" {
			continue
		}
		// A literal IP resolves to itself; a name goes through the OS resolver.
		if a, err := netip.ParseAddr(host); err == nil {
			if !seen[a] {
				seen[a], out = true, append(out, a)
			}
			continue
		}
		ips, err := net.LookupIP(host)
		if err != nil {
			return nil, fmt.Errorf("resolve bypass host %q: %w", host, err)
		}
		for _, ip := range ips {
			a, ok := netip.AddrFromSlice(ip)
			if !ok {
				continue
			}
			a = a.Unmap()
			if !seen[a] {
				seen[a], out = true, append(out, a)
			}
		}
	}
	return out, nil
}
