//go:build linux

package mesh

import (
	"net"

	"golang.zx2c4.com/wireguard/ipc"
)

// openUAPI opens the WireGuard userspace-API socket at
// /var/run/wireguard/<ifname>.sock and returns a listener for it, so the
// standard `wg` tool can read/manage this in-process wireguard-go device.
// Linux only for now (matches configureLink); other platforms get a no-op.
// Needs root (the socket dir is created under /var/run).
func openUAPI(ifname string) (net.Listener, error) {
	file, err := ipc.UAPIOpen(ifname)
	if err != nil {
		return nil, err
	}
	return ipc.UAPIListen(ifname, file)
}
