package mesh

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Home-relay selection (MESH.4 B2b). Until now a node's DERP home was stamped by
// the coordinator — one deployment-wide default region for everybody, which is
// only right for a single-relay deployment. With a relay fleet the node itself is
// the only party that can tell which relay is closest to it, so it measures:
// one STUN round trip per region over the SAME socket that carries DISCO and
// direct WireGuard traffic, then reports the winner as its home. Peers relay to a
// node via THAT node's home, so this directly sets how far a relayed packet
// travels.

const (
	// homeProbeInterval re-measures every region periodically: a laptop that moves
	// between continents (or a link that degrades) should re-home without a
	// reconnect. Cheap — one small UDP datagram per region.
	homeProbeInterval = 5 * time.Minute

	// homeSwitchMargin is the hysteresis that stops the home from flapping between
	// two near-equal regions. Re-homing is not free: it rewrites the node's
	// derp_home, which is pushed to every peer's netmap, and moves the relay link.
	// A new region must be meaningfully faster before it wins.
	homeSwitchMargin = 15 * time.Millisecond
)

// regionRTT is one region's measured round trip, plus the STUN endpoint that
// produced it (which becomes the node's reflexive-probe target once the region
// is chosen as home).
type regionRTT struct {
	Region string
	STUN   netip.AddrPort
	RTT    time.Duration
}

// probeRegions measures the round trip to every region in the DERP map, in
// parallel, over the node's direct-path socket. A region with no STUN endpoint,
// an unresolvable host, or no answer within the probe timeout is simply absent
// from the result — unreachable relays must not be chosen as home.
//
// The measurement is the time to the FIRST STUN response, so a lost packet shows
// up as a retransmit-inflated RTT rather than a failure. That is the honest
// signal for home selection: a lossy path is a bad home even when it is near.
func probeRegions(ctx context.Context, ms *magicSock, m DERPMap, logger *slog.Logger) []regionRTT {
	type result struct {
		r  regionRTT
		ok bool
	}
	results := make([]result, len(m.Regions))
	var wg sync.WaitGroup
	for i, region := range m.Regions {
		hostPort, ok := regionSTUNHostPort(region)
		if !ok {
			continue
		}
		wg.Add(1)
		go func(i int, code, hostPort string) {
			defer wg.Done()
			sa, ok := resolveSTUNServer(ctx, hostPort)
			if !ok {
				return
			}
			start := time.Now()
			if _, err := ms.Reflexive(ctx, sa); err != nil {
				if logger != nil && ctx.Err() == nil {
					logger.Debug("mesh: relay region unreachable for home selection", "region", code, "stun", hostPort, "err", err)
				}
				return
			}
			results[i] = result{r: regionRTT{Region: code, STUN: sa, RTT: time.Since(start)}, ok: true}
		}(i, region.Code, hostPort)
	}
	wg.Wait()

	out := make([]regionRTT, 0, len(results))
	for _, res := range results {
		if res.ok {
			out = append(out, res.r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RTT < out[j].RTT })
	return out
}

// regionSTUNHostPort returns the host:port of the first relay in the region that
// advertises a STUN port. ok=false when none does (that region can't be measured
// and so can't be chosen as home). Pure.
func regionSTUNHostPort(r DERPRegion) (string, bool) {
	for _, n := range r.Nodes {
		if n.HostName != "" && n.STUNPort > 0 {
			return net.JoinHostPort(n.HostName, strconv.Itoa(n.STUNPort)), true
		}
	}
	return "", false
}

// homePref biases home selection toward one class of relay so that switching the
// edge affinity moves the mesh relay home the SAME way — "use my node" lights up
// both the node's edge egress and its relay home. It is a SOFT preference: it
// only narrows the candidate set, never strands a node.
type homePref int

const (
	homeAnyRelay       homePref = iota // no preference — pure latency (default / community)
	homePreferOwn                      // prefer the org's self-hosted relays (affinity "own")
	homePreferPlatform                 // prefer the platform's relays (affinity "platform")
)

// FacilityRelayRegion maps the region an edge session is anchored to onto the
// relay region code that means "the relay in that same facility".
//
// An edge that also runs a relay defaults the relay's label to its own region
// (calabi-edge config), and bff-edge codes a self-hosted relay's region as
// "self-"+label — so a self-hosted facility in edge region R relays as "self-R".
// Nothing is returned for the platform data plane: the platform fleet is ours to
// place, so relay home there stays pure latency, and coord derives the platform
// DERP map from the edge directory keyed by the edge's own region anyway.
//
// A relay whose label was overridden to something other than its edge's region
// simply won't match, and selection falls back to latency. That is the right
// failure: this is a convenience pin, not a contract.
func FacilityRelayRegion(edgeRegion string, preferPlatform bool) string {
	edgeRegion = strings.TrimSpace(edgeRegion)
	if edgeRegion == "" || preferPlatform {
		return ""
	}
	return "self-" + edgeRegion
}

// isSelfHostedRegion reports whether a DERP region code names an org's OWN relay.
// The coordinator prefixes self-hosted relay regions with "self-" when it merges
// them into an org's map (mesh_relays / CompositeDERP), so a node can tell its
// own infrastructure from the platform's with no extra field on the wire.
func isSelfHostedRegion(code string) bool { return strings.HasPrefix(code, "self-") }

// pickHome chooses the home region from a measured (RTT-ascending) set, given the
// node's current home and a soft preference. The current home is KEPT unless
// another region beats it by more than homeSwitchMargin — except when the current
// home didn't answer at all (or the preference just excluded it), where the
// fastest eligible region wins outright (a home we can't reach — or one that
// belongs to the class we just switched away from — is worse than any we can).
// Returns "" only when nothing was measurable, meaning: report nothing and leave
// the coordinator's default in place. Pure.
func pickHome(current string, measured []regionRTT, pref homePref, pinned string) string {
	if len(measured) == 0 {
		return ""
	}
	// A pinned region wins outright, hysteresis included. It names the relay in
	// the SAME facility as the edge this node's tunnels are anchored to, and
	// that is a placement the operator chose — one box per site, both roles on
	// it. Latency must not quietly undo it. Still soft: a pinned region that did
	// not answer falls through to the measurement below rather than stranding
	// the node on a relay it cannot reach.
	if pinned != "" {
		for _, m := range measured {
			if m.Region == pinned {
				return pinned
			}
		}
	}
	// Narrow to the preferred class when it has any measurable region. This is
	// what makes an affinity flip a real switch: when the user picks "own", a
	// self-hosted region — if reachable — becomes the only candidate, so a
	// current platform home is displaced immediately (it's no longer in the set,
	// so the hysteresis below doesn't protect it). Fall back to the whole set
	// when the preferred class is empty: a preference must never leave a node
	// with no home just because its own relay is momentarily down.
	cand := measured
	if pref != homeAnyRelay {
		pool := make([]regionRTT, 0, len(measured))
		for _, m := range measured {
			if isSelfHostedRegion(m.Region) == (pref == homePreferOwn) {
				pool = append(pool, m)
			}
		}
		if len(pool) > 0 {
			cand = pool // still RTT-ascending: built in order from measured
		}
	}
	best := cand[0]
	for _, m := range cand {
		if m.Region != current {
			continue
		}
		// The current home is still eligible and answered: only a materially
		// faster region displaces it.
		if best.RTT+homeSwitchMargin < m.RTT {
			return best.Region
		}
		return current
	}
	return best.Region
}

// stunFor returns the measured STUN endpoint of a region, so the chosen home's
// relay is also the one asked for this node's reflexive address (the endpoint it
// advertises to peers). Pure.
func stunFor(region string, measured []regionRTT) (netip.AddrPort, bool) {
	for _, m := range measured {
		if m.Region == region {
			return m.STUN, true
		}
	}
	return netip.AddrPort{}, false
}
