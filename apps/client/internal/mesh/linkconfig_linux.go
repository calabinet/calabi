//go:build linux

package mesh

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
)

// addSubnetRoutes routes each advertised CIDR (a subnet-router peer's
// allowed-ip outside the overlay range) at the tun, so overlay-external
// destinations flow into WireGuard (MESH.7). Idempotent ("exists" ignored).
func addSubnetRoutes(_ uint64, ifname string, routes []netip.Prefix) error {
	for _, r := range routes {
		out, err := runIP("route", "add", r.String(), "dev", ifname)
		if err != nil && !strings.Contains(strings.ToLower(out), "exists") {
			return fmt.Errorf("ip route add %s: %v: %s", r, err, strings.TrimSpace(out))
		}
	}
	return nil
}

// delSubnetRoutes withdraws routes previously installed by addSubnetRoutes, so a
// CIDR a peer stopped advertising stops being pointed at the tun (where nothing
// would claim it any more — a blackhole).
//
// Scoped to the tun via `dev ifname`: an identical prefix routed at another
// interface — the operator's own static route — is never touched. A route that is
// already gone is not an error (the tun may have been torn down, taking its
// routes with it). Every prefix is attempted even if an earlier one fails: they
// are independent, and stopping early would leave the rest blackholed.
func delSubnetRoutes(_ uint64, ifname string, routes []netip.Prefix) error {
	var errs []error
	for _, r := range routes {
		out, err := runIP("route", "del", r.String(), "dev", ifname)
		if err == nil || routeAlreadyGone(out) {
			continue
		}
		errs = append(errs, fmt.Errorf("ip route del %s: %v: %s", r, err, strings.TrimSpace(out)))
	}
	return errors.Join(errs...)
}

// routeAlreadyGone matches iproute2's two "nothing to delete" replies: ESRCH when
// the route is not in the table, ENODEV when the tun itself is already gone.
// Matched on the message because `ip` exits 2 for both — which is why runIP pins
// the locale (these come from strerror, which glibc DOES translate).
func routeAlreadyGone(out string) bool {
	s := strings.ToLower(out)
	return strings.Contains(s, "no such process") || strings.Contains(s, "cannot find device")
}

// runIP runs iproute2 with the C locale so the "already exists" / "no such
// process" replies this file matches on stay in English on a localized host.
func runIP(args ...string) (string, error) {
	cmd := exec.Command("ip", args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// configureLink assigns the node's overlay /32 to the tun and routes the mesh
// CGNAT range (meshOverlayCIDR) at it by shelling out to iproute2 — the same
// approach wg-quick takes. Needs CAP_NET_ADMIN (run as root).
//
// Idempotent: "exists" errors (the address/route is already present from a prior
// apply) are ignored so repeated netmap updates don't fail. The luid arg is unused
// on Linux (Windows-only; see linkconfig_windows.go).
func configureLink(_ uint64, ifname string, overlay netip.Addr) error {
	steps := [][]string{
		{"link", "set", "dev", ifname, "up"},
		{"address", "add", overlay.String() + "/32", "dev", ifname},
		{"route", "add", meshOverlayCIDR, "dev", ifname},
	}
	for _, args := range steps {
		out, err := runIP(args...)
		if err != nil && !strings.Contains(strings.ToLower(out), "exists") {
			return fmt.Errorf("ip %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(out))
		}
	}
	return nil
}
