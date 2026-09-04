//go:build windows

package mesh

import (
	"errors"
	"fmt"
	"net/netip"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// configureLink assigns the node's overlay /32 to the wintun interface and routes
// the mesh CGNAT range (meshOverlayCIDR) at it, using the IP Helper API via
// winipcfg + the adapter's LUID — the same mechanism WireGuard's own Windows
// client uses. This is preferred over shelling out to netsh: it's idempotent
// (SetIPAddresses replaces the set) and locale-independent (no parsing of
// translated "already exists" strings).
//
// luid is the wintun adapter LUID (WGDatapath.tunLUID); ifname is used only for
// error context. Needs administrator privileges (like creating the tun itself).
func configureLink(luid uint64, ifname string, overlay netip.Addr) error {
	if luid == 0 {
		return fmt.Errorf("mesh: tun %q has no wintun LUID; cannot configure link", ifname)
	}
	l := winipcfg.LUID(luid)

	bits := 32
	if overlay.Is6() {
		bits = 128
	}
	if err := l.SetIPAddresses([]netip.Prefix{netip.PrefixFrom(overlay, bits)}); err != nil {
		return fmt.Errorf("mesh: set tun address %s: %w", overlay, err)
	}

	pfx, err := netip.ParsePrefix(meshOverlayCIDR)
	if err != nil {
		return fmt.Errorf("mesh: parse overlay cidr: %w", err)
	}
	return addWinRoute(l, pfx)
}

// addSubnetRoutes routes each advertised CIDR (a subnet-router / exit peer's
// allowed-ip outside the overlay) at the tun so those destinations flow into
// WireGuard (MESH.7). Idempotent — an already-present route is not an error.
func addSubnetRoutes(luid uint64, ifname string, routes []netip.Prefix) error {
	if len(routes) == 0 {
		return nil
	}
	if luid == 0 {
		return fmt.Errorf("mesh: tun %q has no wintun LUID; cannot add routes", ifname)
	}
	l := winipcfg.LUID(luid)
	for _, r := range routes {
		if err := addWinRoute(l, r); err != nil {
			return err
		}
	}
	return nil
}

// delSubnetRoutes withdraws routes previously installed by addSubnetRoutes, so a
// CIDR a peer stopped advertising stops being pointed at the tun (where nothing
// would claim it any more — a blackhole).
//
// DeleteRoute matches on the adapter LUID, so this can only ever remove routes at
// OUR tun — an identical prefix on another interface is untouched. A route that
// is already gone is not an error. Every prefix is attempted even if an earlier
// one fails: they are independent, and stopping early would leave the rest
// blackholed.
func delSubnetRoutes(luid uint64, ifname string, routes []netip.Prefix) error {
	if len(routes) == 0 {
		return nil
	}
	if luid == 0 {
		return fmt.Errorf("mesh: tun %q has no wintun LUID; cannot remove routes", ifname)
	}
	l := winipcfg.LUID(luid)
	var errs []error
	for _, r := range routes {
		nextHop := netip.IPv4Unspecified()
		if r.Addr().Is6() {
			nextHop = netip.IPv6Unspecified()
		}
		if err := l.DeleteRoute(r, nextHop); err != nil && !routeAlreadyGone(err) {
			errs = append(errs, fmt.Errorf("mesh: remove route %s at tun: %w", r, err))
		}
	}
	return errors.Join(errs...)
}

// routeAlreadyGone reports the benign "no such route" replies DeleteRoute returns
// (its GetIpForwardEntry2 lookup fails first), matched by numeric Win32 code
// rather than a localized message — same reasoning as routeAlreadyExists.
func routeAlreadyGone(err error) bool {
	return errors.Is(err, windows.ERROR_NOT_FOUND) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND)
}

// addWinRoute adds an on-link route (unspecified next hop) at the interface,
// tolerating "already exists" so repeated applies are idempotent.
func addWinRoute(l winipcfg.LUID, pfx netip.Prefix) error {
	nextHop := netip.IPv4Unspecified()
	if pfx.Addr().Is6() {
		nextHop = netip.IPv6Unspecified()
	}
	if err := l.AddRoute(pfx, nextHop, 0); err != nil && !routeAlreadyExists(err) {
		return fmt.Errorf("mesh: route %s at tun: %w", pfx, err)
	}
	return nil
}

// routeAlreadyExists reports the benign "the route/address is already present"
// errors CreateIpForwardEntry2 returns, matched by numeric Win32 code (not a
// localized message).
func routeAlreadyExists(err error) bool {
	return errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) ||
		errors.Is(err, windows.ERROR_ALREADY_EXISTS)
}
