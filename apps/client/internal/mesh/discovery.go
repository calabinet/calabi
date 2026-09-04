package mesh

import (
	"net"
	"net/netip"
)

// filterCandidateIPs reduces a host's raw interface addresses to the ones worth
// advertising as direct endpoints (MESH.4): it drops loopback, link-local,
// multicast, and unspecified addresses, plus anything inside the mesh overlay
// range (100.64.0.0/10) — the tun's own address is reached THROUGH the mesh, not
// a direct path to it — and de-dupes. Private/LAN addresses (RFC1918, ULA) are
// KEPT: two peers on the same LAN reach each other directly by them. Pure, so the
// selection is unit-testable without touching the host's interfaces.
func filterCandidateIPs(addrs []netip.Addr) []netip.Addr {
	overlay := netip.MustParsePrefix(meshOverlayCIDR)
	seen := make(map[netip.Addr]bool, len(addrs))
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		a = a.Unmap()
		if !a.IsValid() || a.IsLoopback() || a.IsUnspecified() ||
			a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
			a.IsInterfaceLocalMulticast() || a.IsMulticast() {
			continue
		}
		if overlay.Contains(a) {
			continue // our own overlay address is not a direct endpoint
		}
		if seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	return out
}

// candidateHostIPs enumerates the unicast addresses on the host's up, non-loopback
// interfaces. Impure (reads the OS interface table); the selection logic lives in
// the pure filterCandidateIPs.
func candidateHostIPs() ([]netip.Addr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var addrs []netip.Addr
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		as, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range as {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if na, ok := netip.AddrFromSlice(ip); ok {
				addrs = append(addrs, na.Unmap())
			}
		}
	}
	return addrs, nil
}

// localEndpoints pairs each usable host address with the given UDP port to form
// the node's candidate direct endpoints.
func localEndpoints(port uint16) ([]netip.AddrPort, error) {
	raw, err := candidateHostIPs()
	if err != nil {
		return nil, err
	}
	ips := filterCandidateIPs(raw)
	eps := make([]netip.AddrPort, 0, len(ips))
	for _, ip := range ips {
		eps = append(eps, netip.AddrPortFrom(ip, port))
	}
	return eps, nil
}
