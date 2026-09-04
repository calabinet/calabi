//go:build !linux

package mesh

import (
	"errors"
	"net/netip"
)

// errSubnetRouterUnsupported: the subnet-router glue (IP forwarding + NAT) isn't
// automated off Linux yet, like the tun route + MagicDNS integration. A node can
// still ADVERTISE routes cross-platform; it just can't auto-configure forwarding
// here — the operator sets it up (or runs the router on Linux).
var errSubnetRouterUnsupported = errors.New("mesh: subnet-router forwarding not supported on this platform")

func EnableSubnetRouter(routes []netip.Prefix) (func(), error) {
	if len(routes) == 0 {
		return func() {}, nil
	}
	return nil, errSubnetRouterUnsupported
}
