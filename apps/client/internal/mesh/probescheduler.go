package mesh

import (
	"context"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

const (
	probeIdle            = time.Minute
	probeCandidateLimit  = 32
	probeAdvertisedLimit = 24 // leave room for authenticated NAT source learning
)

// probeScheduler owns periodic discovery. Only authenticated, decrypted inner
// packets (and local outbound packets) extend activity; transport keepalives do
// not. The forwarding path uses an immutable route table and atomic timestamps.
type probeScheduler struct {
	p            *discoProber
	mu           sync.Mutex
	peers        map[meshproto.DiscoKey]*scheduledPeer
	order        []meshproto.DiscoKey
	cursor       int
	lowCursor    int
	rate         float64
	burst        float64
	tokens       float64
	refill       time.Time
	highTokens   float64
	lowTokens    float64
	wake         chan struct{}
	routes       atomic.Pointer[probeRoutes]
	sent         atomic.Uint64
	failed       atomic.Uint64
	limited      atomic.Uint64
	highSent     atomic.Uint64
	lowSent      atomic.Uint64
	maxWaitNs    atomic.Uint64
	retries      atomic.Uint64
	timeouts     atomic.Uint64
	confirmed    atomic.Uint64
	runs         atomic.Uint64
	paused       atomic.Bool
	replyCursor  int
	replyPending int
	replyTokens  float64
	replyRefill  time.Time
	replyStats   probeReplyStats
	reply        func(meshproto.DiscoKey, discoTxID, netip.AddrPort) error
	// send is replaced only by deterministic tests, before the scheduler runs.
	send func(meshproto.DiscoKey, netip.AddrPort) error
}

type scheduledPeer struct {
	key         meshproto.DiscoKey
	active      atomic.Int64
	candidates  []probeCandidate
	lastSend    time.Time
	lastActive  time.Time
	remoteUntil time.Time
	remoteNext  time.Time
	primary     netip.AddrPort
	replies     []queuedProbeReply
	replyTokens float64
	replyRefill time.Time
}

type probeCandidate struct {
	ep       netip.AddrPort
	next     time.Time
	attempt  int
	learned  bool
	queuedAt time.Time
}

type probeRoutes struct {
	exact    map[netip.Addr]*scheduledPeer
	prefixes map[netip.Prefix]*scheduledPeer
	bits     []int
}

func newProbeScheduler(p *discoProber, rate int) *probeScheduler {
	burst := 10
	if rate <= 20 {
		burst = 5
	}
	s := &probeScheduler{p: p, peers: make(map[meshproto.DiscoKey]*scheduledPeer), rate: float64(rate), burst: float64(burst), tokens: float64(burst), wake: make(chan struct{}, 1)}
	s.send = p.sendProbe
	s.reply = func(key meshproto.DiscoKey, tx discoTxID, from netip.AddrPort) error {
		return p.ms.sendDisco(from, key, discoMessage{Type: discoPong, Tx: tx, Src: from})
	}
	s.highTokens = s.burst * .8
	s.lowTokens = s.burst * .2
	return s
}

func (s *probeScheduler) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// update changes candidates without restarting unchanged peers or trusting stale
// paths. In particular, grant refreshes and endpoint ordering are not events.
func (s *probeScheduler) update(peers []Peer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	keep := make(map[meshproto.DiscoKey]bool, len(peers))
	for _, peer := range peers {
		key := peer.DiscoKey
		if key.IsZero() {
			continue
		}
		keep[key] = true
		sp := s.peer(key)
		eps := boundedProbeEndpoints(peer.Endpoints)
		next := make([]probeCandidate, 0, min(len(eps), probeCandidateLimit))
		for _, ep := range eps {
			if !ep.IsValid() || (len(next) > 0 && next[len(next)-1].ep == ep) {
				continue
			}
			c := probeCandidate{ep: ep}
			for _, old := range sp.candidates {
				if old.ep == ep {
					c = old
					c.learned = false
					break
				}
			}
			next = append(next, c)
			if len(next) == probeCandidateLimit {
				break
			}
		}
		// A topology refresh must not restart discovery of live learned paths.
		for _, old := range sp.candidates {
			if !old.learned || len(next) >= probeCandidateLimit {
				continue
			}
			duplicate := false
			for _, c := range next {
				if c.ep == old.ep {
					duplicate = true
					break
				}
			}
			if !duplicate {
				next = append(next, old)
			}
		}
		sp.candidates = next
	}
	for key := range s.peers {
		if !keep[key] {
			s.replyPending -= len(s.peers[key].replies)
			delete(s.peers, key)
		}
	}
	s.order = s.order[:0]
	for key := range s.peers {
		s.order = append(s.order, key)
	}
	sort.Slice(s.order, func(i, j int) bool { return s.order[i].String() < s.order[j].String() })
	// Retire removed peers immediately, even if an old pong arrives afterwards.
	s.p.mu.Lock()
	for key := range s.p.paths {
		if !keep[key] {
			delete(s.p.paths, key)
		}
	}
	for key := range s.p.learned {
		if !keep[key] {
			delete(s.p.learned, key)
		}
	}
	for tx, pp := range s.p.pending {
		if !keep[pp.peer] {
			delete(s.p.pending, tx)
		}
	}
	s.p.mu.Unlock()
	s.signal()
}

// Preserve both LAN and public families even on hosts with many virtual
// adapters. Merely taking the first private-first 32 addresses could omit the
// only public NAT endpoint, and leave no slot for a learned symmetric-NAT port.
func boundedProbeEndpoints(input []netip.AddrPort) []netip.AddrPort {
	eps := append([]netip.AddrPort(nil), input...)
	sort.Slice(eps, func(i, j int) bool {
		if eps[i].Addr().IsPrivate() != eps[j].Addr().IsPrivate() {
			return eps[i].Addr().IsPrivate()
		}
		return eps[i].Compare(eps[j]) < 0
	})
	out := make([]netip.AddrPort, 0, min(len(eps), probeAdvertisedLimit))
	seen := map[netip.AddrPort]bool{}
	classes := map[int]bool{}
	appendEndpoint := func(ep netip.AddrPort) {
		if ep.IsValid() && !seen[ep] && len(out) < probeAdvertisedLimit {
			out = append(out, ep)
			seen[ep] = true
		}
	}
	for _, ep := range eps {
		if !ep.IsValid() {
			continue
		}
		class := 0
		if ep.Addr().Is6() {
			class += 1
		}
		if !ep.Addr().IsPrivate() {
			class += 2
		}
		if !classes[class] {
			appendEndpoint(ep)
			classes[class] = true
		}
	}
	for _, ep := range eps {
		appendEndpoint(ep)
	}
	return out
}

func (s *probeScheduler) peer(key meshproto.DiscoKey) *scheduledPeer {
	sp := s.peers[key]
	if sp == nil {
		sp = &scheduledPeer{key: key}
		s.peers[key] = sp
	}
	return sp
}

// setRoutes receives the same allowed-ips and exit selection as WireGuard,
// after the controller's route policy. Longest-prefix matching also covers
// subnet aliases and return traffic from an exit device.
func (s *probeScheduler) setRoutes(cfg WGConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := &probeRoutes{exact: make(map[netip.Addr]*scheduledPeer), prefixes: make(map[netip.Prefix]*scheduledPeer)}
	bits := map[int]bool{}
	for _, peer := range cfg.Peers {
		if peer.DiscoKey.IsZero() {
			continue
		}
		sp := s.peer(peer.DiscoKey)
		for _, prefix := range peer.AllowedIPs {
			if !prefix.IsValid() {
				continue
			}
			if isDefaultRoute(prefix) && !peer.PublicKey.Equal(cfg.ExitNode) {
				continue
			}
			prefix = prefix.Masked()
			if prefix.Bits() == prefix.Addr().BitLen() {
				r.exact[prefix.Addr()] = sp
			} else {
				r.prefixes[prefix] = sp
				bits[prefix.Bits()] = true
			}
		}
	}
	for b := range bits {
		r.bits = append(r.bits, b)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(r.bits)))
	s.routes.Store(r)
}

func (s *probeScheduler) observe(addr netip.Addr) {
	r := s.routes.Load()
	if r == nil {
		return
	}
	sp := r.exact[addr]
	if sp == nil {
		for _, bits := range r.bits {
			if bits > addr.BitLen() {
				continue
			}
			if sp = r.prefixes[netip.PrefixFrom(addr, bits).Masked()]; sp != nil {
				break
			}
		}
	}
	if sp != nil {
		now := time.Now().UnixNano()
		// Coalesce hot traffic to one atomic store and wake per second per peer.
		old := sp.active.Load()
		if now-old >= int64(time.Second) && sp.active.CompareAndSwap(old, now) {
			if old == 0 || now-old > int64(probeIdle) {
				s.signal()
			}
		}
	}
}

func (s *probeScheduler) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sp := range s.peers {
		sp.replies = nil
		sp.remoteUntil = time.Time{}
		sp.remoteNext = time.Time{}
		for i := range sp.candidates {
			sp.candidates[i].next = time.Time{}
			sp.candidates[i].attempt = 0
			sp.candidates[i].queuedAt = time.Time{}
		}
	}
	s.replyPending = 0
	s.p.mu.Lock()
	clear(s.p.paths)
	clear(s.p.pending)
	clear(s.p.learned)
	s.p.mu.Unlock()
	s.signal()
}

// A known peer's authenticated ping may be its first handshake attempt while
// the relay is unavailable. Give the reverse path a short discovery window,
// once per minute. Pings and pongs never extend genuine business activity.
func (s *probeScheduler) request(key meshproto.DiscoKey) { s.requestAt(key, time.Now()) }

func (s *probeScheduler) requestAt(key meshproto.DiscoKey, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sp := s.peers[key]
	if sp == nil || now.Before(sp.remoteNext) {
		return
	}
	if stamp := sp.active.Load(); stamp != 0 && now.Sub(time.Unix(0, stamp)) <= probeIdle {
		return
	}
	sp.remoteUntil = now.Add(5 * time.Second)
	sp.remoteNext = now.Add(time.Minute)
	for i := range sp.candidates {
		sp.candidates[i].next = time.Time{}
		sp.candidates[i].attempt = 0
		sp.candidates[i].queuedAt = time.Time{}
	}
	s.signal()
}

// step is shared by the real clock loop and deterministic capacity tests.
// The round-robin cursor persists across ticks, so a failing or busy peer cannot
// monopolise a device's budget. No goroutine or queued job is created per peer.
func (s *probeScheduler) step(now time.Time) {
	s.runs.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.paused.Load() {
		return
	}
	s.drainPongs(now)
	if s.refill.IsZero() {
		s.refill = now
	}
	s.tokens = min(s.burst, s.tokens+max(0, now.Sub(s.refill).Seconds())*s.rate)
	elapsed := max(0, now.Sub(s.refill).Seconds())
	s.highTokens = min(s.burst*.8, s.highTokens+elapsed*s.rate*.8)
	s.lowTokens = min(s.burst*.2, s.lowTokens+elapsed*s.rate*.2)
	s.refill = now
	for priority := 0; priority < 2; priority++ {
		budget, cursor := &s.highTokens, &s.cursor
		if priority == 1 {
			budget, cursor = &s.lowTokens, &s.lowCursor
		}
		for n := 0; n < len(s.order); n++ {
			if *cursor >= len(s.order) {
				*cursor = 0
			}
			sp := s.peers[s.order[*cursor]]
			*cursor++
			stamp := sp.active.Load()
			business := stamp != 0 && now.Sub(time.Unix(0, stamp)) <= probeIdle
			if !business && !now.Before(sp.remoteUntil) {
				continue
			}
			active := time.Unix(0, stamp)
			if business && (sp.lastActive.IsZero() || active.Sub(sp.lastActive) > probeIdle) {
				for i := range sp.candidates {
					sp.candidates[i].next = time.Time{}
					sp.candidates[i].attempt = 0
					sp.candidates[i].queuedAt = time.Time{}
				}
			}
			if business {
				sp.lastActive = active
			}
			if !sp.lastSend.IsZero() && now.Sub(sp.lastSend) < time.Second/3 {
				continue
			}
			s.p.mu.Lock()
			pathState, valid := s.p.paths[sp.key]
			valid = valid && now.Sub(pathState.confirmed) <= pathTTL
			s.p.mu.Unlock()
			path := pathState.ep
			if valid {
				sp.primary = path
			} else if sp.primary.IsValid() {
				for i := range sp.candidates {
					if sp.candidates[i].ep == sp.primary {
						sp.candidates[i].next = now
						sp.candidates[i].attempt = 0
						sp.candidates[i].queuedAt = now
					}
				}
				sp.primary = netip.AddrPort{}
			}
			// Authenticated learned addresses support symmetric NAT, but are bounded.
			learned := s.p.learnedFor(sp.key)
			kept := sp.candidates[:0]
			for _, c := range sp.candidates {
				keep := !c.learned
				for _, ep := range learned {
					if c.ep == ep {
						keep = true
						break
					}
				}
				if keep {
					kept = append(kept, c)
				}
			}
			sp.candidates = kept
			for _, ep := range learned {
				found := false
				for _, c := range sp.candidates {
					if c.ep == ep {
						found = true
						break
					}
				}
				if !found && len(sp.candidates) < probeCandidateLimit {
					sp.candidates = append(sp.candidates, probeCandidate{ep: ep, learned: true})
				}
			}
			chosen := -1
			for i := range sp.candidates {
				c := sp.candidates[i]
				if valid && c.ep == path && c.next.After(pathState.confirmed.Add(probeInterval)) {
					c.next = pathState.confirmed.Add(probeInterval)
					sp.candidates[i].next = c.next
				}
				if now.Before(c.next) {
					continue
				}
				if c.queuedAt.IsZero() {
					c.queuedAt = c.next
					if c.queuedAt.IsZero() {
						c.queuedAt = now
					}
					sp.candidates[i].queuedAt = c.queuedAt
				}
				low := c.attempt >= 3 && !(valid && c.ep == path)
				if low != (priority == 1) {
					continue
				}
				if chosen < 0 || c.next.Before(sp.candidates[chosen].next) {
					chosen = i
				}
				if valid && c.ep == path {
					chosen = i
					break
				}
			}
			if chosen < 0 {
				continue
			}
			if s.tokens < 1 || *budget < 1 {
				s.limited.Add(1)
				// Retry this peer first after refill. Advancing here can repeatedly
				// skip every other peer when each timer tick refills one token.
				*cursor--
				break
			}
			s.tokens--
			*budget--
			c := &sp.candidates[chosen]
			queuedAt := c.queuedAt
			if wait := now.Sub(queuedAt); wait > 0 {
				s.recordMaxWait(uint64(wait))
			}
			if c.attempt > 0 {
				s.retries.Add(1)
			}
			err := s.send(sp.key, c.ep)
			s.sent.Add(1)
			if priority == 0 {
				s.highSent.Add(1)
			} else {
				s.lowSent.Add(1)
			}
			if err != nil {
				s.failed.Add(1)
			}
			sp.lastSend = now
			c.queuedAt = time.Time{}
			if valid && c.ep == path {
				c.attempt = 0
				c.next = now.Add(probeInterval)
			} else {
				backoff := []time.Duration{time.Second, 2 * time.Second, 5 * time.Second, 15 * time.Second, 30 * time.Second, time.Minute, 5 * time.Minute}
				i := min(c.attempt, len(backoff)-1)
				delay := backoff[i]
				if valid {
					delay = time.Minute
				}
				// Deterministic per-peer jitter avoids aligned fleet-wide retries.
				jitter := time.Duration(int(sp.key[0])%21-10) * delay / 100
				c.next = now.Add(delay + jitter)
				c.attempt++
			}
		}
	}
	// Reap once per scheduler turn, rather than once per emitted ping.
	s.p.reapPending(now)
	s.p.reapLearned(now)
}

func (s *probeScheduler) recordMaxWait(n uint64) {
	for old := s.maxWaitNs.Load(); n > old; old = s.maxWaitNs.Load() {
		if s.maxWaitNs.CompareAndSwap(old, n) {
			return
		}
	}
}

func (s *probeScheduler) run(ctx context.Context) {
	t := time.NewTimer(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
			s.step(time.Now())
		case <-t.C:
			s.step(time.Now())
		}
		delay := s.nextDelay(time.Now())
		if !t.Stop() {
			select {
			case <-t.C:
			default:
			}
		}
		t.Reset(delay)
	}
}

// Sleep until useful work is due. An active phone must not poll at 50 Hz merely
// to send a maintenance probe every five seconds. Packet arrivals wake it.
func (s *probeScheduler) nextDelay(now time.Time) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.paused.Load() {
		return time.Minute
	}
	next := now.Add(time.Minute)
	ready := func(tokens, rate float64) time.Time {
		if tokens >= 1 {
			return now
		}
		return now.Add(time.Duration((1 - tokens) / rate * float64(time.Second)))
	}
	choose := func(at time.Time) {
		if at.Before(next) {
			next = at
		}
	}
	s.p.mu.Lock()
	defer s.p.mu.Unlock()
	for _, sp := range s.peers {
		if len(sp.replies) > 0 {
			at := ready(s.replyTokens, s.rate*2)
			if !sp.replyRefill.IsZero() {
				if peerAt := ready(sp.replyTokens, 6); peerAt.After(at) {
					at = peerAt
				}
			}
			choose(at)
		}
		stamp := sp.active.Load()
		if (stamp == 0 || now.Sub(time.Unix(0, stamp)) > probeIdle) && !now.Before(sp.remoteUntil) {
			continue
		}
		path, valid := s.p.paths[sp.key]
		valid = valid && now.Sub(path.confirmed) <= pathTTL
		for _, c := range sp.candidates {
			at := c.next
			if at.IsZero() {
				at = now
			}
			low := c.attempt >= 3 && !(valid && c.ep == path.ep)
			budget, rate := s.highTokens, s.rate*.8
			if low {
				budget, rate = s.lowTokens, s.rate*.2
			}
			for _, due := range []time.Time{ready(s.tokens, s.rate), ready(budget, rate), sp.lastSend.Add(time.Second / 3)} {
				if due.After(at) {
					at = due
				}
			}
			choose(at)
		}
	}
	for _, pp := range s.p.pending {
		choose(pp.sent.Add(pendingTTL + time.Millisecond))
	}
	return max(time.Millisecond, next.Sub(now))
}
