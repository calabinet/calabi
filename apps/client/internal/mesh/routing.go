package mesh

import "net/netip"

// Routing points the host's addressing and routes at the mesh tun.
//
// On a desktop the client does this itself, one OS call per change
// (linkconfig_*.go, exitroute_*.go). A phone app may not: iOS and Android hand a
// VPN its addresses, routes and DNS as ONE settings object, applied by the
// platform (NEPacketTunnelNetworkSettings, VpnService.Builder). The platform's
// Routing therefore accumulates these calls into the settings it applies; the
// datapath's decisions — what to route, what to withdraw, what local wins —
// stay in one place for both.
type Routing interface {
	// ConfigureLink assigns the node's overlay address to the tun and routes the
	// overlay range (100.64.0.0/10) at it. Called again when the address changes.
	ConfigureLink(overlay netip.Addr) error
	// AddSubnetRoutes routes the given peer-advertised prefixes at the tun.
	AddSubnetRoutes(routes []netip.Prefix) error
	// DelSubnetRoutes withdraws prefixes an earlier AddSubnetRoutes installed.
	DelSubnetRoutes(routes []netip.Prefix) error
	// EnableExitRoutes sends every destination through the tun except lanKeep and
	// bypass, the control-plane addresses the tunnel itself travels over. cleanup
	// restores the previous default routing.
	//
	// A platform that keeps the client's own sockets out of the tunnel some other
	// way (VpnService.protect; a packet tunnel provider's own traffic on iOS) may
	// ignore bypass.
	EnableExitRoutes(bypass []netip.Addr, lanKeep []netip.Prefix) (cleanup func(), err error)
	// OwnSocketsBypassTunnel reports whether the client's own sockets stay out of
	// the tunnel whatever the routes say. If they do, a full tunnel cannot
	// capture the direct-path socket, so direct paths stay on while an exit
	// device is in use; otherwise they pause and every peer goes through the relay.
	OwnSocketsBypassTunnel() bool
}

// osRouting is the desktop Routing: this process edits the OS routing table
// itself, through the per-OS implementations.
type osRouting struct{ d *WGDatapath }

func (r osRouting) ConfigureLink(overlay netip.Addr) error {
	return configureLink(r.d.tunLUID(), r.d.ifname, overlay)
}

func (r osRouting) AddSubnetRoutes(routes []netip.Prefix) error {
	return addSubnetRoutes(r.d.tunLUID(), r.d.ifname, routes)
}

func (r osRouting) DelSubnetRoutes(routes []netip.Prefix) error {
	return delSubnetRoutes(r.d.tunLUID(), r.d.ifname, routes)
}

func (r osRouting) EnableExitRoutes(bypass []netip.Addr, lanKeep []netip.Prefix) (func(), error) {
	return enableExitRoutes(r.d.tunLUID(), r.d.ifname, bypass, lanKeep)
}

// OwnSocketsBypassTunnel is false: a desktop full tunnel routes every address
// through the tun, including a peer's public IP that the direct-path socket sends to.
func (osRouting) OwnSocketsBypassTunnel() bool { return false }
