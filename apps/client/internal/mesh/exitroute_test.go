package mesh

import (
	"net/netip"
	"testing"
)

// pickPhysicalRoute must reproduce the kernel's best-route choice: longest
// prefix, then lowest metric, and it must never return a row on the excluded
// (tun) interface — otherwise the coord/relay bypass would be pinned back
// through the tunnel we're hijacking and the WireGuard transport would loop.
func TestPickPhysicalRoute(t *testing.T) {
	const physLUID, tunLUID = uint64(11), uint64(99)
	gw := netip.MustParseAddr("192.168.1.1")
	rows := []routeEntry{
		// physical default via the LAN gateway
		{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Metric: 25, NextHop: gw, LUID: physLUID},
		// a more-specific static route on the same physical NIC, on-link
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Metric: 5, NextHop: netip.IPv4Unspecified(), LUID: physLUID},
		// the split-default we (hypothetically) already put on the tun — must be skipped
		{Prefix: netip.MustParsePrefix("0.0.0.0/1"), Metric: 0, NextHop: netip.IPv4Unspecified(), LUID: tunLUID},
	}

	// A public IP falls to the default route via the gateway (tun row ignored).
	got, ok := pickPhysicalRoute(netip.MustParseAddr("8.8.8.8"), rows, tunLUID)
	if !ok || got.NextHop != gw || got.LUID != physLUID {
		t.Fatalf("public dst: got %+v ok=%v, want default via %s on %d", got, ok, gw, physLUID)
	}

	// A dst inside 10/8 prefers the longer prefix, even though its metric detail
	// differs — longest-prefix wins over the /0.
	got, ok = pickPhysicalRoute(netip.MustParseAddr("10.1.2.3"), rows, tunLUID)
	if !ok || got.Prefix.Bits() != 8 {
		t.Fatalf("10/8 dst: got %+v ok=%v, want the /8", got, ok)
	}

	// If the ONLY matching route is on the tun, there is no physical path.
	only := []routeEntry{{Prefix: netip.MustParsePrefix("0.0.0.0/1"), NextHop: netip.IPv4Unspecified(), LUID: tunLUID}}
	if _, ok := pickPhysicalRoute(netip.MustParseAddr("8.8.8.8"), only, tunLUID); ok {
		t.Fatal("dst reachable only via the tun must yield ok=false")
	}
}

// Lowest metric breaks a tie between equal-length prefixes.
func TestPickPhysicalRouteMetricTieBreak(t *testing.T) {
	lo := netip.MustParseAddr("192.168.1.1")
	hi := netip.MustParseAddr("192.168.2.1")
	rows := []routeEntry{
		{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Metric: 100, NextHop: hi, LUID: 1},
		{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Metric: 10, NextHop: lo, LUID: 2},
	}
	got, ok := pickPhysicalRoute(netip.MustParseAddr("1.2.3.4"), rows, 0)
	if !ok || got.NextHop != lo {
		t.Fatalf("tie-break: got %+v, want lowest-metric nexthop %s", got, lo)
	}
}

func TestParseDarwinRouteGet(t *testing.T) {
	// A normal off-link destination: gateway + interface both present.
	viaGW := `   route to: 8.8.8.8
destination: default
       mask: default
    gateway: 192.168.1.254
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>`
	if gw, iface := parseDarwinRouteGet(viaGW); gw != "192.168.1.254" || iface != "en0" {
		t.Fatalf("off-link: gw=%q iface=%q, want 192.168.1.254/en0", gw, iface)
	}

	// An on-link destination: no numeric gateway, only the interface — callers
	// pin via -interface in that case.
	onLink := `   route to: 192.168.1.50
destination: 192.168.1.0
       mask: 255.255.255.0
  interface: en0
      flags: <UP,DONE,CLONING>`
	gw, iface := parseDarwinRouteGet(onLink)
	if iface != "en0" {
		t.Fatalf("on-link: iface=%q, want en0", iface)
	}
	if ip, err := netip.ParseAddr(gw); err == nil && ip.IsValid() {
		t.Fatalf("on-link: gateway %q parsed as an IP, want none", gw)
	}
}
