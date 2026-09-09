package mesh

import (
	"fmt"
	"net/netip"
	"strings"
)

// How a subnet route is written, and how wide it may be.
//
// One definition, imported by every place that reads a route from a human: the
// CLI (--advertise-routes / --alias-routes), the daemon config file and the
// :7400 console's POST handler. The coordinator enforces the same width rule
// again on its own side (calabi-coord/internal/core/routelimits.go) because a
// client is not a place to put a rule that protects a shared resource — but the
// error a person actually reads should come from here, at the moment they type
// it, not from a server round trip that silently drops the route.

// AdvertiseMinBitsV4 is the widest IPv4 subnet route that may be published: a
// /24. Anything shorter is refused.
//
// The limit exists because every published route is aliased, and an alias costs its own size
// in pool addresses: a /24 costs 256, a /16 costs 65,536 — 256x the default
// per-meshnet budget, so a /16 could never be granted one anyway. Before this
// rule it was accepted, silently failed to get an alias, and fell back to
// publishing the real CIDR, i.e. straight back into the address collision the
// whole mechanism exists to avoid. Refusing it here turns a silent, permanent
// failure into one sentence at the moment of typing.
//
// Someone with a flat /16 LAN publishes the /24s they actually need instead.
// That is more typing and it is also more honest: the default budget grants one
// /24, so "how many subnets may I publish" stops depending on how the operator
// happened to write the mask.
//
// IPv6 is deliberately not limited. The alias pool is IPv4-only, so no v6 route
// is aliased and none of the above applies to it.
const AdvertiseMinBitsV4 = 24

// ParseRoute parses one subnet route as a person writes it.
//
// A bare address is a host route: "192.168.1.22" means 192.168.1.22/32. Users
// publishing a single machine think of it as an address, not as a subnet with a
// mask that cannot be anything else, and writing "/32" after it is pure
// ceremony. Both spellings are accepted; FormatRoute renders it back the short
// way.
//
// The result is masked to its network, so 192.168.1.5/24 comes back as
// 192.168.1.0/24 rather than being rejected — the operator named a subnet by an
// address inside it, which is a normal thing to do.
func ParseRoute(s string) (netip.Prefix, error) {
	p, err := ParseExclude(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	if err := checkRouteWidth(p); err != nil {
		return netip.Prefix{}, err
	}
	return p, nil
}

// ParseExclude parses a prefix the same way but WITHOUT the width limit, for the
// consumer side (RoutePolicy.Excludes).
//
// The limit is about publishing: an over-wide route costs the shared alias pool
// and can never be granted an alias. Refusing a route is the opposite — naming a
// whole /16 to keep out of this machine's routing table is a reasonable and
// cheap thing to say, and it costs nobody anything. Applying the publish limit
// here would have removed a capability for no reason at all.
func ParseExclude(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Prefix{}, fmt.Errorf("empty route")
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		// No "/bits": accept a bare address as a host route.
		addr, aerr := netip.ParseAddr(s)
		if aerr != nil {
			return netip.Prefix{}, fmt.Errorf("%q is not an IP address or CIDR", s)
		}
		p = netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen())
	}
	return p.Masked(), nil
}

// checkRouteWidth rejects an IPv4 route wider than AdvertiseMinBitsV4, naming
// the smaller prefixes the operator should publish instead — an error that says
// only "too broad" leaves them guessing at what is allowed.
func checkRouteWidth(p netip.Prefix) error {
	if !p.Addr().Is4() || p.Bits() >= AdvertiseMinBitsV4 {
		return nil
	}
	return fmt.Errorf("%s is wider than a /%d: publish the specific /%d subnets you need (e.g. %s) instead",
		p, AdvertiseMinBitsV4, AdvertiseMinBitsV4,
		netip.PrefixFrom(p.Addr(), AdvertiseMinBitsV4).Masked())
}

// ParseRouteList parses a comma-separated list of routes, masked to their
// networks and de-duplicated in input order. Empty input yields nil.
func ParseRouteList(csv string) ([]netip.Prefix, error) {
	csv = strings.TrimSpace(csv)
	if csv == "" {
		return nil, nil
	}
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	for _, s := range strings.Split(csv, ",") {
		if strings.TrimSpace(s) == "" {
			continue
		}
		p, err := ParseRoute(s)
		if err != nil {
			return nil, err
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out, nil
}

// FormatRoute renders a route the way ParseRoute accepts it: a host route as a
// bare address, everything else as CIDR. The inverse of the bare-address rule
// above, so what the console shows is what a person would type.
func FormatRoute(p netip.Prefix) string {
	if p.IsSingleIP() {
		return p.Addr().String()
	}
	return p.String()
}

// RouteProblem is one stored route that could not be used, kept with the reason
// so the caller can log both.
type RouteProblem struct {
	Raw string
	Err error
}

// SplitRouteList parses routes that come from STORED config (the daemon's YAML,
// the creds file) rather than from someone typing right now: it returns the
// usable ones and the rejects, instead of failing on the first bad entry.
//
// The distinction matters and is not stylistic. A route the operator is typing
// should be refused loudly — they are there, they can fix it. A route already
// sitting in a config file is read at daemon start, and failing there takes the
// WHOLE mesh session down: no overlay address, no peer-to-peer traffic, no other
// routes, because of one netmask that was legal when it was written. The width
// limit was added after these files existed, so that case is not hypothetical —
// it is what every subnet router publishing a /16 will hit on upgrade.
func SplitRouteList(items []string) (keep []netip.Prefix, bad []RouteProblem) {
	seen := map[netip.Prefix]bool{}
	for _, raw := range items {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		p, err := ParseRoute(raw)
		if err != nil {
			bad = append(bad, RouteProblem{Raw: strings.TrimSpace(raw), Err: err})
			continue
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		keep = append(keep, p)
	}
	return keep, bad
}

// ProblemStrings renders a RouteProblem list for a log line.
func ProblemStrings(bad []RouteProblem) []string {
	out := make([]string, 0, len(bad))
	for _, b := range bad {
		out = append(out, b.Err.Error())
	}
	return out
}
