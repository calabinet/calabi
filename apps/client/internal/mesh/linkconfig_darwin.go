//go:build darwin

package mesh

import (
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

// configureLink assigns the node's overlay address to the utun interface and
// routes the mesh CGNAT range (meshOverlayCIDR) at it by shelling out to ifconfig
// + route — the same wg-quick approach the Linux path takes with iproute2. A utun
// is point-to-point, so the address is set as <local> <peer> with the overlay IP
// for both (a host route to self). Needs root (like creating the utun itself).
//
// The luid arg is Windows-only; ignored here.
func configureLink(_ uint64, ifname string, overlay netip.Addr) error {
	ip := overlay.String()
	// `ifconfig utunN inet <ip> <ip> up` — assign + bring up. Tolerate an
	// already-configured address so a repeated apply doesn't fail.
	if out, err := exec.Command("ifconfig", ifname, "inet", ip, ip, "up").CombinedOutput(); err != nil &&
		!strings.Contains(strings.ToLower(string(out)), "exists") {
		return fmt.Errorf("ifconfig %s inet %s: %w: %s", ifname, ip, err, strings.TrimSpace(string(out)))
	}
	return addDarwinRoute(meshOverlayCIDR, ifname)
}

// addSubnetRoutes routes each advertised CIDR at the utun (MESH.7). Idempotent —
// route's "File exists" is ignored.
func addSubnetRoutes(_ uint64, ifname string, routes []netip.Prefix) error {
	for _, r := range routes {
		if err := addDarwinRoute(r.String(), ifname); err != nil {
			return err
		}
	}
	return nil
}

// delSubnetRoutes withdraws routes previously installed by addSubnetRoutes, so a
// CIDR a peer stopped advertising stops being pointed at the utun (where nothing
// would claim it any more — a blackhole).
//
// Scoped to the utun via -interface. A route that is already gone is not an error
// ("not in table"). Every prefix is attempted even if an earlier one fails.
func delSubnetRoutes(_ uint64, ifname string, routes []netip.Prefix) error {
	var errs []error
	for _, r := range routes {
		out, err := exec.Command("route", "-n", "delete", "-net", r.String(), "-interface", ifname).CombinedOutput()
		if err == nil || routeAlreadyGone(string(out)) {
			continue
		}
		errs = append(errs, fmt.Errorf("route delete -net %s -interface %s: %w: %s",
			r, ifname, err, strings.TrimSpace(string(out))))
	}
	return errors.Join(errs...)
}

// routeAlreadyGone matches BSD route(8)'s "nothing to delete" replies.
func routeAlreadyGone(out string) bool {
	s := strings.ToLower(out)
	return strings.Contains(s, "not in table") || strings.Contains(s, "no such process")
}

// addDarwinRoute adds an interface-scoped route for cidr at ifname. macOS `route`
// reports "File exists" when the route is already present; that's benign.
func addDarwinRoute(cidr, ifname string) error {
	out, err := exec.Command("route", "-n", "add", "-net", cidr, "-interface", ifname).CombinedOutput()
	if err != nil && !strings.Contains(strings.ToLower(string(out)), "exists") {
		return fmt.Errorf("route add -net %s -interface %s: %w: %s", cidr, ifname, err, strings.TrimSpace(string(out)))
	}
	return nil
}
