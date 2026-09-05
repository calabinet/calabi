package mesh

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// probeInterval is how often the prober re-pings known peers' endpoints — to
// discover new working paths and to keep a NAT binding (and the path's freshness)
// alive.
const probeInterval = 5 * time.Second

// pathTTL bounds how long a validated direct path is trusted without a fresh
// pong. The prober re-pings well within it, so a live path stays confirmed and a
// dead one expires (the transport slice falls back to relay when it does).
const pathTTL = 15 * time.Second

// pathSticky is how long an already-validated path is kept while it stays QUIET
// — after this much silence any sibling that answers takes over, whatever its
// round-trip. Without it the last pong of each round wins, so a peer reachable at
// two endpoints at once — two container networks between the same pair of hosts,
// a machine on two LANs, v4 and v6 — flips its path every probe round: the
// transport choice churns and the "direct path found" line (which only prints on
// a change) repeats forever.
//
// Deliberately BELOW pathTTL: a path that stops answering must be replaced by a
// working sibling endpoint while bestPath still trusts it, not after bestPath has
// already given up and dropped the peer to the relay. A write failure doesn't
// wait for it at all — the bind calls invalidatePath, and the next pong takes
// over immediately.
const pathSticky = 2 * probeInterval

// How much quicker a sibling endpoint has to answer before traffic moves onto it
// while the current path is still perfectly alive.
//
// Why this exists. "Direct" means "not through the relay" — it does NOT mean
// "over the LAN". Two machines on one LAN advertise both their private address
// and the public one their NAT maps them to, and BOTH answer: the public one
// works because the router hairpins the packet back in. They are not remotely
// equivalent. Measured on a home LAN: the private path does ~500 MB/s, the
// hairpinned one ~0.3 MB/s — the packet leaves for the ISP and comes back, over
// an uplink sized for upload, on a router that usually hairpins in software.
// First-pong-wins would lock onto whichever answered first and pathSticky would
// then keep it there forever.
//
// Round-trip is the discriminator rather than "is it an RFC1918 address": a
// private address is a poor proxy for a short path once docker bridges, VPN
// adapters, hypervisor NATs and multi-homed hosts are in play, and RTT also
// separates two PUBLIC paths of very different quality, which no address
// heuristic can.
//
// Both conditions must hold, so the two guards cover different failure modes:
// the ratio ignores a sibling that is merely a bit quicker, and the floor stops
// two sub-millisecond LAN endpoints from trading the path on scheduling jitter.
const pathFasterRatio = 2
const pathFasterFloor = 3 * time.Millisecond

// pendingTTL caps how long an unanswered ping stays pending before it's reaped.
const pendingTTL = 10 * time.Second

// learnedTTL bounds how long a DISCO-learned candidate endpoint keeps being
// probed without fresh traffic from it — long enough to ride out a few missed
// packets, short enough to forget a peer's stale per-session NAT port.
const learnedTTL = 30 * time.Second

// discoProber drives DISCO path discovery (MESH.4 B3): it pings each peer's
// candidate endpoints and records which answer, exposing the best validated
// direct path per peer via bestPath. The bind consumes that (as a pathFinder) to
// decide, per packet, whether a peer's WireGuard traffic goes direct or via the
// relay — so a path only ever carries traffic after a pong proved it works, and
// stops carrying it as soon as it goes stale (pathTTL) or a write fails
// (invalidatePath).
type discoProber struct {
	ms     *magicSock
	logger *slog.Logger

	mu      sync.Mutex
	pending map[discoTxID]pendingProbe
	paths   map[meshproto.DiscoKey]peerPath
	// learned holds, per peer, the endpoints its OWN authenticated DISCO traffic
	// arrived from (plus when each was last seen). Probe pings these ALONGSIDE the
	// netmap endpoints so a symmetric-NAT peer — reachable only at the
	// per-destination port it used to reach us, which never appears in its netmap
	// (that carries its STUN port) — still gets a validated return path instead of
	// the relay. Reaped after learnedTTL without a refresh.
	learned map[meshproto.DiscoKey]map[netip.AddrPort]time.Time
}

type pendingProbe struct {
	peer meshproto.DiscoKey
	ep   netip.AddrPort
	sent time.Time
}

type peerPath struct {
	ep        netip.AddrPort
	confirmed time.Time
	// rtt is how long the pong that last confirmed this endpoint took to come
	// back. Refreshed every probe round (the path we're on is probed like any
	// other), so a path that degrades is compared at its current cost, not the
	// one it had when it was adopted.
	rtt time.Duration
}

// quicker reports whether a sibling endpoint answered fast enough to justify
// moving traffic off the path already carrying it. See pathFasterRatio.
func quicker(candidate, incumbent time.Duration) bool {
	return candidate*pathFasterRatio < incumbent && incumbent-candidate >= pathFasterFloor
}

func newDiscoProber(ms *magicSock, logger *slog.Logger) *discoProber {
	p := &discoProber{
		ms:      ms,
		logger:  logger,
		pending: make(map[discoTxID]pendingProbe),
		paths:   make(map[meshproto.DiscoKey]peerPath),
		learned: make(map[meshproto.DiscoKey]map[netip.AddrPort]time.Time),
	}
	ms.setPongHandler(p.onPong)
	return p
}

// onPong records a validated direct path: the endpoint we pinged (bound to this
// pong by tx id) reaches the peer. A pong for an unknown tx, or from a different
// peer than we pinged, is ignored (it can't validate a path we didn't probe).
func (p *discoProber) onPong(peer meshproto.DiscoKey, tx discoTxID, _ netip.AddrPort) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pp, ok := p.pending[tx]
	if !ok || pp.peer != peer {
		return
	}
	delete(p.pending, tx)
	now := time.Now()
	rtt := now.Sub(pp.sent)
	prev, had := p.paths[peer]
	switch {
	case !had:
		p.paths[peer] = peerPath{ep: pp.ep, confirmed: now, rtt: rtt}
		if p.logger != nil {
			p.logger.Info("mesh direct path found", "peer_disco", peer.String(),
				"endpoint", pp.ep.String(), "rtt", rtt.Round(time.Microsecond).String())
		}
	case prev.ep == pp.ep:
		// The path we're on answered again: refresh it (and its cost), say nothing.
		p.paths[peer] = peerPath{ep: pp.ep, confirmed: now, rtt: rtt}
	case now.Sub(prev.confirmed) > pathSticky:
		// The path we're on has gone quiet for longer than a couple of probe
		// rounds while this sibling answers — move before bestPath expires the
		// peer to the relay. Liveness beats speed here: any working path is
		// better than dropping to the relay.
		p.adopt(peer, pp.ep, rtt, prev, now, "quiet_for", now.Sub(prev.confirmed).Round(time.Second).String())
	case quicker(rtt, prev.rtt):
		// Both answer, but this one is in a different league — the LAN path
		// against the hairpinned public one, most often. Move.
		p.adopt(peer, pp.ep, rtt, prev, now, "was_rtt", prev.rtt.Round(time.Microsecond).String())
	default:
		// A sibling endpoint works too, and is no quicker in any way that
		// matters. Keep the one already carrying traffic rather than churn.
	}
}

// adopt moves the peer onto ep and logs why. Callers hold p.mu.
func (p *discoProber) adopt(peer meshproto.DiscoKey, ep netip.AddrPort, rtt time.Duration,
	prev peerPath, now time.Time, whyKey, whyVal string) {
	p.paths[peer] = peerPath{ep: ep, confirmed: now, rtt: rtt}
	if p.logger != nil {
		p.logger.Info("mesh direct path changed", "peer_disco", peer.String(),
			"endpoint", ep.String(), "rtt", rtt.Round(time.Microsecond).String(),
			"was", prev.ep.String(), whyKey, whyVal)
	}
}

// Probe pings every candidate endpoint of every peer that carries a disco key,
// registering each ping so its pong validates that endpoint. Called on each
// netmap and on the periodic tick.
func (p *discoProber) Probe(peers []Peer) {
	now := time.Now()
	p.reapPending(now)
	p.reapLearned(now)
	for _, peer := range peers {
		if peer.DiscoKey.IsZero() {
			continue
		}
		learned := p.learnedFor(peer.DiscoKey)
		if p.logger != nil {
			p.logger.Debug("mesh probe peer", "netmap_eps", len(peer.Endpoints), "learned_eps", len(learned))
		}
		sent := make(map[netip.AddrPort]struct{})
		probe := func(ep netip.AddrPort) {
			if !ep.IsValid() {
				return
			}
			if _, dup := sent[ep]; dup {
				return
			}
			sent[ep] = struct{}{}
			tx, err := p.ms.SendPing(peer.DiscoKey, ep)
			if err != nil {
				return
			}
			p.mu.Lock()
			// Stamped per send, not from the round's `now`: every ping in a round
			// would otherwise share one start time, and an endpoint probed 20th
			// would measure slower than one probed 1st by the length of the send
			// loop — a bias that decides which path wins now that RTT does.
			p.pending[tx] = pendingProbe{peer: peer.DiscoKey, ep: ep, sent: time.Now()}
			p.mu.Unlock()
		}
		for _, ep := range peer.Endpoints {
			probe(ep)
		}
		// Also probe endpoints learned from the peer's OWN DISCO packets. A
		// symmetric-NAT peer is reachable only at the per-destination port it used
		// to reach us — that port never appears in its netmap (which carries its
		// STUN port), so without this the cone side never validates a return path
		// and stays on the relay. See learnCandidate.
		for _, ep := range learned {
			probe(ep)
		}
	}
}

// bestPath returns the peer's validated direct endpoint if one was confirmed
// within pathTTL. The transport slice prefers it over the relay.
func (p *discoProber) bestPath(peer meshproto.DiscoKey) (netip.AddrPort, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pp, ok := p.paths[peer]
	if !ok || time.Since(pp.confirmed) > pathTTL {
		return netip.AddrPort{}, false
	}
	return pp.ep, true
}

// pathRTT reports the round-trip of the peer's current direct path — the same
// number bestPath's choice is made on. Reported state only: the console shows it
// so that "direct, and a public address" (a LAN pair whose traffic is hairpinning
// through the ISP) can be told apart from "direct, over the LAN" at a glance,
// which was exactly what nobody could see when that shipped.
func (p *discoProber) pathRTT(peer meshproto.DiscoKey) (time.Duration, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pp, ok := p.paths[peer]
	if !ok || time.Since(pp.confirmed) > pathTTL {
		return 0, false
	}
	return pp.rtt, true
}

// invalidatePath retires a peer's validated path — called by the bind when a
// direct write to it fails, so traffic returns to the relay at once instead of
// waiting out pathTTL. The next probe round re-validates the path if it recovers.
func (p *discoProber) invalidatePath(peer meshproto.DiscoKey) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.paths, peer)
}

func (p *discoProber) reapPending(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for tx, pp := range p.pending {
		if now.Sub(pp.sent) > pendingTTL {
			delete(p.pending, tx)
		}
	}
}

// learnCandidate records an endpoint a peer's authenticated DISCO traffic arrived
// FROM, so the next Probe round pings it even though the peer never advertised it.
// This is the missing half of symmetric↔cone hole punching: the cone side learns
// the symmetric peer's real per-destination port here (its netmap endpoint is the
// STUN port, which its symmetric NAT won't accept our packets on) and can then
// validate — and use — a direct return path instead of the relay. Only ever called
// for authenticated DISCO from a known peer (see meshBind.noteDiscoSource), so it
// can't be steered by a forged source.
func (p *discoProber) learnCandidate(peer meshproto.DiscoKey, ep netip.AddrPort) {
	if peer.IsZero() || !ep.IsValid() {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	m := p.learned[peer]
	if m == nil {
		m = make(map[netip.AddrPort]time.Time)
		p.learned[peer] = m
	}
	_, existed := m[ep]
	m[ep] = time.Now()
	if !existed && p.logger != nil {
		p.logger.Debug("mesh learned disco source", "ep", ep.String())
	}
}

// learnedFor snapshots the endpoints currently learned for a peer (see Probe).
func (p *discoProber) learnedFor(peer meshproto.DiscoKey) []netip.AddrPort {
	p.mu.Lock()
	defer p.mu.Unlock()
	m := p.learned[peer]
	if len(m) == 0 {
		return nil
	}
	out := make([]netip.AddrPort, 0, len(m))
	for ep := range m {
		out = append(out, ep)
	}
	return out
}

// reapLearned forgets learned endpoints not refreshed within learnedTTL, so a
// peer's stale per-session NAT port isn't probed forever.
func (p *discoProber) reapLearned(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for peer, m := range p.learned {
		for ep, seen := range m {
			if now.Sub(seen) > learnedTTL {
				delete(m, ep)
			}
		}
		if len(m) == 0 {
			delete(p.learned, peer)
		}
	}
}

// run re-probes the current peer set on a fixed interval until ctx ends. peersFn
// supplies the latest peers (from the newest netmap).
func (p *discoProber) run(ctx context.Context, peersFn func() []Peer) {
	t := time.NewTicker(probeInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.Probe(peersFn())
		}
	}
}
