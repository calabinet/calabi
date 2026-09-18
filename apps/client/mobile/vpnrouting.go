package mobile

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"sync"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/calabi/calabi/apps/client/internal/mesh"
)

// meshOverlay is the range every node address comes from; the VPN always routes
// it, whatever else it carries.
var meshOverlay = netip.MustParsePrefix("100.64.0.0/10")

// networkSettings is what the platform applies to the VPN in one go: Android's
// VpnService.Builder, iOS's NEPacketTunnelNetworkSettings. JSON because it
// crosses the gomobile boundary as a string.
type networkSettings struct {
	// Addresses are the VPN interface's own addresses ("100.64.0.5/32").
	Addresses []string `json:"addresses"`
	// Routes are the destinations sent into the VPN. Everything else stays on
	// the device's own network.
	Routes []string `json:"routes"`
	MTU    int      `json:"mtu"`
}

// vpnRouting is the phone's mesh.Routing. The datapath decides, one call at a
// time, what the host should route; a phone can only apply all of it at once.
// So each call updates the desired state and re-applies the whole of it through
// the platform, which answers with the tun descriptor to use from then on.
type vpnRouting struct {
	platform Platform
	tun      *swapTUN
	mtu      int
	// open turns a descriptor into a tun device (openTUN).
	open func(fd int) (tun.Device, error)

	mu      sync.Mutex
	overlay netip.Addr
	subnets map[netip.Prefix]bool
	exit    bool
	lanKeep []netip.Prefix
	applied string // the settings last applied, so an unchanged state is not re-applied
	fd      int    // the descriptor behind the current device; -1 = none
	// routesChanged runs after new settings are applied. A connection opened
	// before them may now route into the VPN with its old source address, which
	// no peer accepts; the core drops its pooled connections here.
	routesChanged func()
}

var _ mesh.Routing = (*vpnRouting)(nil)

func newVPNRouting(p Platform, t *swapTUN, mtu int) *vpnRouting {
	return &vpnRouting{platform: p, tun: t, mtu: mtu, open: openTUN, subnets: map[netip.Prefix]bool{}, fd: -1}
}

// openTUN opens a descriptor the platform returned. A variable so tests, which
// have no VPN descriptor to open, can supply an in-memory device.
var openTUN = tunFromFD

func (r *vpnRouting) ConfigureLink(overlay netip.Addr) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.overlay = overlay
	return r.applyLocked()
}

func (r *vpnRouting) AddSubnetRoutes(routes []netip.Prefix) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range routes {
		r.subnets[p.Masked()] = true
	}
	return r.applyLocked()
}

func (r *vpnRouting) DelSubnetRoutes(routes []netip.Prefix) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range routes {
		delete(r.subnets, p.Masked())
	}
	return r.applyLocked()
}

// EnableExitRoutes routes all of IPv4 except lanKeep into the VPN. bypass is
// ignored: the tunnel's own sockets are kept out of the VPN by the socket hook
// (VpnService.protect), not by routes.
func (r *vpnRouting) EnableExitRoutes(_ []netip.Addr, lanKeep []netip.Prefix) (func(), error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.exit, r.lanKeep = true, append([]netip.Prefix(nil), lanKeep...)
	if err := r.applyLocked(); err != nil {
		r.exit, r.lanKeep = false, nil
		return nil, err
	}
	return func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.exit, r.lanKeep = false, nil
		_ = r.applyLocked()
	}, nil
}

// OwnSocketsBypassTunnel is true: every socket the core opens goes through the
// socket hook (VpnService.protect on Android), so an exit device's full tunnel
// does not capture the direct-path socket.
func (r *vpnRouting) OwnSocketsBypassTunnel() bool { return true }

// settingsLocked renders the desired state. Caller holds r.mu.
func (r *vpnRouting) settingsLocked() networkSettings {
	s := networkSettings{
		Addresses: []string{netip.PrefixFrom(r.overlay, r.overlay.BitLen()).String()},
		MTU:       r.mtu,
	}
	routes := []netip.Prefix{meshOverlay}
	for p := range r.subnets {
		routes = append(routes, p)
	}
	if r.exit {
		routes = append(routes, subtractPrefixes(netip.MustParsePrefix("0.0.0.0/0"), r.lanKeep)...)
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Addr() != routes[j].Addr() {
			return routes[i].Addr().Less(routes[j].Addr())
		}
		return routes[i].Bits() < routes[j].Bits()
	})
	for _, p := range routes {
		s.Routes = append(s.Routes, p.String())
	}
	return s
}

// applyLocked hands the desired state to the platform and switches the datapath
// onto the descriptor it returns. Nothing is applied before the node has an
// address: a VPN cannot be established without one, and the routes gathered so
// far go out with the first address. Caller holds r.mu.
func (r *vpnRouting) applyLocked() error {
	if !r.overlay.IsValid() {
		return nil
	}
	b, err := json.Marshal(r.settingsLocked())
	if err != nil {
		return err
	}
	settings := string(b)
	if settings == r.applied {
		return nil
	}
	fd, err := r.platform.ApplyNetwork(settings)
	if err != nil {
		return fmt.Errorf("mobile: apply VPN settings: %w", err)
	}
	// iOS keeps the same tunnel descriptor across settings changes; Android
	// hands back a new one. Re-opening the SAME descriptor would close it out
	// from under the datapath when the old device is swapped away.
	if int(fd) != r.fd {
		dev, err := r.open(int(fd))
		if err != nil {
			return fmt.Errorf("mobile: open tun descriptor %d: %w", fd, err)
		}
		if err := r.tun.Swap(dev); err != nil {
			return err
		}
		r.fd = int(fd)
	}
	r.applied = settings
	if r.routesChanged != nil {
		r.routesChanged()
	}
	return nil
}

// subtractPrefixes returns base minus every prefix in remove, as the fewest
// prefixes that cover the rest. Android before API 33 cannot exclude a route
// from the VPN, so "everything but the LAN" has to be spelled out as the
// addresses that are left.
func subtractPrefixes(base netip.Prefix, remove []netip.Prefix) []netip.Prefix {
	base = base.Masked()
	overlaps := false
	for _, rm := range remove {
		rm = rm.Masked()
		if rm.Addr().Is4() != base.Addr().Is4() {
			continue
		}
		if rm.Bits() <= base.Bits() && rm.Contains(base.Addr()) {
			return nil // base lies entirely inside something removed
		}
		if base.Overlaps(rm) {
			overlaps = true
		}
	}
	if !overlaps {
		return []netip.Prefix{base}
	}
	bits := base.Bits() + 1
	lo := netip.PrefixFrom(base.Addr(), bits)
	hiAddr := base.Addr()
	// The upper half starts where the new bit is set.
	b := hiAddr.AsSlice()
	b[(bits-1)/8] |= 0x80 >> ((bits - 1) % 8)
	hiAddr, _ = netip.AddrFromSlice(b)
	hi := netip.PrefixFrom(hiAddr, bits)
	return append(subtractPrefixes(lo, remove), subtractPrefixes(hi, remove)...)
}
