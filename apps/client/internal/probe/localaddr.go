// localaddr.go — what counts as a LOCAL upstream.
//
// This predicate has two callers with the same stake in it:
//
//   - tunnel creation (cmd/calabi validateLocalUpstream), where a public
//     upstream would turn the client into an open relay;
//   - the wizard's reachability check (CheckOnce below), which dials whatever
//     address the caller hands it. The :7400 console has no auth of its own, so
//     an unguarded probe endpoint is a port scanner anyone on that port can aim
//     at the rest of the machine's network.
//
// It lives here, in the package that does the dialling, so the guard sits next
// to the act it guards and there is exactly one definition of "local".
package probe

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// IsLocalIP reports whether ip is a local/intranet address a tunnel may forward
// to: loopback, RFC1918/ULA private, link-local, or the unspecified address.
func IsLocalIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

// ValidateLocalTarget enforces that an address is a LOCAL/intranet upstream,
// never an arbitrary public address. It requires a host:port, then:
//   - IP literal  → must be local (loopback / 10. / 172.16. / 192.168. / LL).
//   - "localhost" or a *.local/.lan/.internal/.home.arpa name → accepted.
//   - any other hostname → RESOLVED; every resolved IP must be local. This is
//     what catches "www.google.com" (resolves to a public IP). Unresolvable
//     names are rejected (can't prove local). Resolution is best-effort with a
//     short timeout. Mirrors the wizard's client-side check (TunnelWizard.tsx),
//     which can't resolve DNS so it only catches the missing-port / public-IP
//     cases and leaves the resolve check to here.
//
// An empty address returns nil: callers report "missing local address" in their
// own words, and this function has nothing to say about it.
func ValidateLocalTarget(addr string) error {
	s := strings.TrimSpace(addr)
	if s == "" {
		return nil
	}
	if allDigits(s) {
		return nil // bare numeric port → implicit loopback host
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return fmt.Errorf("local address %q must be host:port (e.g. 127.0.0.1:8080 or localhost:3000)", s)
	}
	if !allDigits(port) {
		return fmt.Errorf("local address %q has an invalid port %q", s, port)
	}
	if ip := net.ParseIP(host); ip != nil {
		if IsLocalIP(ip) {
			return nil
		}
		return errPublicUpstream(host)
	}
	lower := strings.ToLower(host)
	if lower == "localhost" || hasLocalHostnameSuffix(lower) {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		return fmt.Errorf("local address host %q could not be resolved to a local/intranet IP; "+
			"use a loopback / private (10./172.16./192.168.) address or a LAN hostname", host)
	}
	for _, a := range ips {
		if !IsLocalIP(a.IP) {
			return errPublicUpstream(host)
		}
	}
	return nil
}

// NormalizeLocalTarget accepts "host:port" verbatim or a bare numeric port (→
// 127.0.0.1:port) so the config can read `local: 8080`. A non-numeric token
// with no colon (e.g. a hostname like "myhost") is returned AS-IS, not turned
// into "127.0.0.1:<hostname>" — that bogus host:port (port = the hostname) was
// the cause of `local=127.0.0.1:www.google.com`. ValidateLocalTarget rejects
// the missing-port form for console creates.
func NormalizeLocalTarget(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if allDigits(s) {
		return "127.0.0.1:" + s
	}
	return s
}

// hasLocalHostnameSuffix reports whether a (lowercased) hostname uses one of the
// conventional local-network suffixes, which we trust as intranet without a DNS
// lookup.
func hasLocalHostnameSuffix(lower string) bool {
	for _, suf := range []string{".local", ".lan", ".internal", ".home.arpa"} {
		if strings.HasSuffix(lower, suf) {
			return true
		}
	}
	return false
}

func errPublicUpstream(host string) error {
	return fmt.Errorf("local address %q points to a public address; a tunnel may only forward to a "+
		"local/intranet upstream (loopback, 10./172.16./192.168., link-local) or a LAN hostname", host)
}

// allDigits reports whether s is non-empty and made up solely of ASCII digits
// (a bare port).
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
