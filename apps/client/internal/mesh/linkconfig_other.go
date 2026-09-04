//go:build !linux && !windows && !darwin

package mesh

import (
	"fmt"
	"net/netip"
)

// configureLink is not automated on this platform (Linux uses iproute2, Windows
// uses winipcfg, macOS uses ifconfig+route; other BSDs land later). The WireGuard
// device is already up; SetConfig degrades the returned errLinkConfigManual to a
// warning and the operator assigns the address + route by hand. The error text
// carries the exact overlay /32 and the CGNAT route to add.
func configureLink(_ uint64, ifname string, overlay netip.Addr) error {
	return fmt.Errorf("%w: assign %s/32 to interface %q and route %s at it",
		errLinkConfigManual, overlay, ifname, meshOverlayCIDR)
}

// addSubnetRoutes is a no-op on platforms without automated link config.
func addSubnetRoutes(uint64, string, []netip.Prefix) error { return nil }

// delSubnetRoutes is likewise a no-op: nothing was installed to withdraw.
func delSubnetRoutes(uint64, string, []netip.Prefix) error { return nil }
