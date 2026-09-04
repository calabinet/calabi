//go:build !linux && !windows && !darwin

package mesh

import (
	"fmt"
	"net/netip"
)

// enableExitRoutes is not automated on this platform (Linux, Windows and macOS
// each have a native implementation). The error is logged as a warning by
// applyExitNode; the mesh itself keeps working, only the full-tunnel default
// route isn't taken over automatically.
func enableExitRoutes(uint64, string, []netip.Addr, []netip.Prefix) (func(), error) {
	return nil, fmt.Errorf("%w: exit-node default routing", errLinkConfigManual)
}
