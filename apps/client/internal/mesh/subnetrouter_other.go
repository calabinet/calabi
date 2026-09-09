//go:build !linux

package mesh

import (
	"errors"
	"net/netip"
)

// errSubnetRouterUnsupported: the subnet-router glue (IP forwarding + NAT) isn't
// automated off Linux yet, like the tun route + MagicDNS integration. The :7400
// console therefore refuses to TAKE ON these roles here
// statusapi.newAdvertisementRefused) — advertising without forwarding is a
// blackhole for the peers that believe it. --advertise-routes and the config file
// still work, for an operator who has wired up forwarding by hand.
var errSubnetRouterUnsupported = errors.New("mesh: subnet-router forwarding not supported on this platform")

// SubnetRouterSupported reports whether this build can forward for the routes it
// advertises. False here — see the comment above, and SubnetRouterSupported in
// subnetrouter_linux.go for why the answer lives beside the backend.
func SubnetRouterSupported() bool { return false }

func EnableSubnetRouter(routes []netip.Prefix) (func(), error) {
	if len(routes) == 0 {
		return func() {}, nil
	}
	return nil, errSubnetRouterUnsupported
}

// EnableSubnetAliases is unavailable off Linux for the same reason
// EnableSubnetRouter is: there is no forwarding or NAT backend here. A node that
// cannot forward cannot be a subnet router at all, so it can never hold an
// alias either — the console refuses the role up front
// (statusapi.newAdvertisementRefused), and this is the backstop.
func EnableSubnetAliases(aliases []SubnetAlias) (func(), error) {
	if len(aliases) == 0 {
		return func() {}, nil
	}
	return nil, errSubnetRouterUnsupported
}

// probeSubnetAlias is a definite "no" off Linux, for the same reason
// EnableSubnetAliases is unavailable: the rewrite is an iptables NETMAP rule.
// Definite, not unknown — there is nothing here that could later turn out to
// work, so this is an answer rather than a failure to look.
func probeSubnetAlias() (AliasSupport, string) {
	return AliasSupportNo, "subnet alias rewrites are Linux-only (they are `iptables` NETMAP rules)"
}
