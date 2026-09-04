package mesh

import (
	"context"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/calabi/calabi/apps/client/internal/mesh/derp"
	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// relayPool is the node's set of live relay links (MESH.4 B2b — the multi-relay
// fleet). With one relay in the deployment this is exactly the single link that
// came before it; with a fleet it is what makes cross-region peers reachable at
// all.
//
// The rule it implements: a node LISTENS on its own home relay, and SENDS to a
// peer via THAT PEER's home relay. Relays don't talk to each other — each only
// forwards between the nodes connected to it — so if A (home: lax) sent B (home:
// sgp) a packet through lax, sgp is where B is listening and the packet would be
// dropped. A therefore opens a link to sgp as well. Both nodes keep their own
// home link open, which is how each remains reachable.
//
// Links are dialed LAZILY and never from the send path: Send is on WireGuard's
// hot path and must not block on a TCP handshake, so a missing link is dialed in
// the background while that packet takes the home relay (which reaches the peer
// whenever it is homed there, and is dropped otherwise — WireGuard retransmits).
type relayPool struct {
	self   meshproto.NodeKey
	priv   [meshproto.KeyLen]byte
	onRecv derp.RecvFunc
	logger *slog.Logger

	// pingEvery / deadAfter are the liveness sweep's timings (see keepalive).
	// Fields rather than constants so a test can run the sweep in milliseconds.
	pingEvery time.Duration
	deadAfter time.Duration
	stop      chan struct{} // closed by Close; stops the sweep

	mu      sync.Mutex
	home    string // address of this node's own home relay (the fallback for sends)
	grant   []byte // coordinator's current relay authorization (R0'); nil until a netmap arrives
	clients map[string]*derp.Client
	dialing map[string]bool
	closed  bool
}

// relayDialTimeout bounds one background relay dial.
const relayDialTimeout = 10 * time.Second

const (
	// relayPingInterval is how often each live link is pinged. The relay echoes a
	// Pong (pkg/relay's hub, since MESH.0 — the whole fleet answers), so a link
	// that answers is proven alive END TO END, which a successful write is not.
	relayPingInterval = 15 * time.Second
	// relayDeadAfter is how long a link may go without a single frame from the
	// relay before the pool tears it down and re-dials. Three missed keepalives:
	// long enough not to churn a link over one lost packet, short enough that a
	// machine coming out of standby is back on the meshnet in under a minute.
	relayDeadAfter = 45 * time.Second
)

// relayKeepalivePing is the payload every keepalive carries. The contents are
// irrelevant — the relay echoes whatever it is given — but the documented shape
// is 8 bytes, and RTT accounting would use it if it ever lands.
var relayKeepalivePing = make([]byte, 8)

func newRelayPool(self meshproto.NodeKey, priv [meshproto.KeyLen]byte, onRecv derp.RecvFunc, logger *slog.Logger) *relayPool {
	return newRelayPoolTimed(self, priv, onRecv, logger, relayPingInterval, relayDeadAfter)
}

// newRelayPoolTimed is newRelayPool with the liveness timings overridden, so a
// test can watch a link be reaped without waiting three quarters of a minute.
func newRelayPoolTimed(self meshproto.NodeKey, priv [meshproto.KeyLen]byte, onRecv derp.RecvFunc, logger *slog.Logger, pingEvery, deadAfter time.Duration) *relayPool {
	p := &relayPool{
		self:      self,
		priv:      priv,
		onRecv:    onRecv,
		logger:    logger,
		pingEvery: pingEvery,
		deadAfter: deadAfter,
		stop:      make(chan struct{}),
		clients:   make(map[string]*derp.Client),
		dialing:   make(map[string]bool),
	}
	go p.keepalive()
	return p
}

// keepalive is the pool's liveness loop, started with the pool and stopped by
// Close.
//
// It exists because nothing else in the datapath can tell a live relay link from
// a half-open one. WireGuard's own keepalive keeps WRITING to the socket every
// 25s, and on a machine that just resumed from standby those writes succeed —
// into a send buffer whose retransmits nobody will ever answer. Before this loop
// such a link stayed in the pool as a silent black hole and left it only when a
// write finally errored, tens of seconds to minutes later. That window is the
// "woke the laptop and the remote desktop is a black screen" symptom: the overlay
// looks up, the routes are installed, no TCP connection is ever reset, so nothing
// upstack ever learns that it should reconnect.
func (p *relayPool) keepalive() {
	t := time.NewTicker(p.pingEvery)
	defer t.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-t.C:
			p.sweep()
		}
	}
}

// sweep pings every link, reaps the ones that have gone quiet, and makes sure the
// home link is up. Reaping only removes the link — the next Send re-dials — but
// the HOME link is re-dialed here, because that is the one peers need this node
// to be listening on even while it is sending nothing itself.
func (p *relayPool) sweep() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	links := make(map[string]*derp.Client, len(p.clients))
	for addr, c := range p.clients {
		links[addr] = c
	}
	home := p.home
	p.mu.Unlock()

	for addr, c := range links {
		switch {
		case linkDone(c):
			p.reap(addr, c, "relay closed the link")
		case c.Idle() > p.deadAfter:
			p.reap(addr, c, "no frame from the relay within the deadline")
		default:
			if err := c.Ping(relayKeepalivePing); err != nil {
				p.reap(addr, c, "keepalive write failed")
			}
		}
	}

	p.mu.Lock()
	redial := home != "" && !p.closed && p.clients[home] == nil
	p.mu.Unlock()
	if redial {
		p.dial(home)
	}
}

// linkDone reports whether a link's read loop has already exited (the relay hung
// up, or the socket errored) without blocking on it.
func linkDone(c *derp.Client) bool {
	select {
	case <-c.Done():
		return true
	default:
		return false
	}
}

// ResetLinks tears down every link and re-dials the home one. Called when the
// machine has just come back from sleep: every socket the pool holds predates the
// suspend and is, with near certainty, one the far side has already forgotten.
// Proving that one link at a time through the sweep would cost the user a
// black-holed meshnet for the length of a sweep — on the one occasion when a
// human is sitting there watching it.
func (p *relayPool) ResetLinks() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	clients := p.clients
	p.clients = make(map[string]*derp.Client, len(clients))
	home := p.home
	p.mu.Unlock()

	for _, c := range clients {
		_ = c.Close()
	}
	if p.logger != nil && len(clients) > 0 {
		p.logger.Info("mesh: relay links reset after resume; re-dialing", "links", len(clients))
	}
	if home != "" {
		p.dial(home)
	}
}

// SetGrant records the coordinator's latest relay authorization, taken from the
// netmap. Links read it lazily (derp.Auth.Grant is a function) so a relay that
// re-challenges an hours-old link gets the CURRENT grant, not the one that link
// was dialed with.
func (p *relayPool) SetGrant(g []byte) {
	p.mu.Lock()
	p.grant = g
	p.mu.Unlock()
}

// auth is what every link this pool dials presents when challenged.
func (p *relayPool) auth() derp.Auth {
	return derp.Auth{Priv: p.priv, Grant: p.currentGrant}
}

func (p *relayPool) currentGrant() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.grant
}

// DialHome opens the node's first relay link synchronously and makes it the home.
//
// The address is recorded even when the dial fails, so ordinary send-path
// re-dialing (clientFor) can pick it up. Two things make an initial failure
// survivable rather than fatal: hole punching means a node with no relay link is
// degraded, not unreachable; and under R0' the coordinator's relay grant arrives
// with the netmap, i.e. legitimately AFTER this first attempt.
func (p *relayPool) DialHome(ctx context.Context, addr string) error {
	p.mu.Lock()
	if p.home == "" {
		p.home = addr
	}
	p.mu.Unlock()
	c, err := derp.Dial(ctx, addr, p.self, p.auth(), p.onRecv, p.logger)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clients[addr] = c
	p.home = addr
	return nil
}

// Send relays one packet to dst via the relay at addr — the peer's home relay.
// An empty addr (peer with no known home, or a region missing from the map)
// means the node's own home relay, which is the pre-fleet behaviour. If the
// requested link isn't up yet it is dialed in the background and this packet
// falls back to the home link rather than blocking.
func (p *relayPool) Send(addr string, dst meshproto.NodeKey, ciphertext []byte) error {
	c, use := p.clientFor(addr)
	if c == nil {
		return net.ErrClosed
	}
	if err := c.Send(dst, ciphertext); err != nil {
		p.drop(use, c)
		return err
	}
	return nil
}

// clientFor resolves the link to use for one send, kicking off a background dial
// for a link that isn't up. Returns the client and the address it belongs to (for
// error attribution).
func (p *relayPool) clientFor(addr string) (*derp.Client, string) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, ""
	}
	if addr == "" {
		addr = p.home
	}
	if c := p.clients[addr]; c != nil {
		p.mu.Unlock()
		return c, addr
	}
	home := p.home
	hc := p.clients[home]
	p.mu.Unlock()

	p.dial(addr) // background; this packet takes the home link
	return hc, home
}

// drop removes a link whose send failed, so the next send re-dials instead of
// writing into a dead socket.
func (p *relayPool) drop(addr string, c *derp.Client) { p.reap(addr, c, "send failed") }

// reap closes a link and removes it from the pool. Guarded against reaping a link
// that was already replaced by a newer dial. reason says which of the several
// ways a link can die this one was — worth telling apart in a log, because "no
// frame from the relay" is a path problem and "relay closed the link" is not.
func (p *relayPool) reap(addr string, c *derp.Client, reason string) {
	p.mu.Lock()
	if p.clients[addr] == c {
		delete(p.clients, addr)
	} else {
		c = nil
	}
	p.mu.Unlock()
	if c != nil {
		_ = c.Close()
		if p.logger != nil {
			p.logger.Warn("mesh: relay link dropped; will re-dial", "relay", addr, "reason", reason)
		}
	}
}

// dial opens a link in the background (idempotent per address). A failure is
// logged, not retried on a timer: the next send through that relay tries again.
func (p *relayPool) dial(addr string) {
	if addr == "" {
		return
	}
	p.mu.Lock()
	if p.closed || p.clients[addr] != nil || p.dialing[addr] {
		p.mu.Unlock()
		return
	}
	p.dialing[addr] = true
	p.mu.Unlock()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), relayDialTimeout)
		defer cancel()
		c, err := derp.Dial(ctx, addr, p.self, p.auth(), p.onRecv, p.logger)
		p.mu.Lock()
		delete(p.dialing, addr)
		switch {
		case err != nil:
			p.mu.Unlock()
			if p.logger != nil {
				p.logger.Warn("mesh: relay link dial failed", "relay", addr, "err", err)
			}
			return
		case p.closed || p.clients[addr] != nil:
			p.mu.Unlock() // shut down, or another dial won the race
			_ = c.Close()
			return
		}
		p.clients[addr] = c
		p.mu.Unlock()
		if p.logger != nil {
			p.logger.Info("mesh relay link up", "relay", addr)
		}
	}()
}

// Reconcile keeps the pool aligned with the latest netmap: make sure this node's
// own home relay is connected (peers relay to it there), and warm a link to every
// relay a peer is homed at, so the first packet to that peer doesn't have to fall
// back. Nothing is torn down — an old link costs one idle TCP connection and
// keeps working for peers whose netmap hasn't caught up yet.
func (p *relayPool) Reconcile(selfRelay string, peerRelays []string) {
	if selfRelay != "" {
		p.setHome(selfRelay)
	}
	for _, addr := range peerRelays {
		p.dial(addr)
	}
}

// setHome points the node at the relay its own home region resolves to. The
// switch only happens once that link is actually up: until then the previous home
// keeps carrying traffic (and keeps receiving, which is what peers still expect).
func (p *relayPool) setHome(addr string) {
	p.mu.Lock()
	if p.closed || p.home == addr {
		p.mu.Unlock()
		return
	}
	if p.clients[addr] != nil {
		prev := p.home
		p.home = addr
		p.mu.Unlock()
		if p.logger != nil {
			p.logger.Info("mesh home relay switched", "relay", addr, "previous", prev)
		}
		return
	}
	p.mu.Unlock()
	p.dial(addr) // a later Reconcile completes the switch once the link is up
}

// Addrs lists every relay the pool currently holds a link to. The exit-node step
// pins them to the physical link: with a full tunnel engaged, a relay reached
// through the tun would loop WireGuard's own transport back into it.
func (p *relayPool) Addrs() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, 0, len(p.clients))
	for addr := range p.clients {
		out = append(out, addr)
	}
	return out
}

// Home is the address of the node's current home relay (reported in status).
func (p *relayPool) Home() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.home
}

// Close tears down every link and stops the liveness sweep. Idempotent: the
// datapath's own error paths can reach it more than once.
func (p *relayPool) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	close(p.stop)
	clients := p.clients
	p.clients = make(map[string]*derp.Client)
	p.mu.Unlock()
	for _, c := range clients {
		_ = c.Close()
	}
	return nil
}

// relayAddrsByRegion maps each region code in the DERP map to the address of its
// first usable relay — the address a node homed in that region is reachable at.
// Pure. A region whose relays advertise no host/port is absent (there is nothing
// to dial), which makes peers homed there fall back to the local home relay.
func relayAddrsByRegion(m DERPMap) map[string]string {
	out := make(map[string]string, len(m.Regions))
	for _, r := range m.Regions {
		for _, n := range r.Nodes {
			if n.HostName == "" || n.DERPPort <= 0 {
				continue
			}
			out[r.Code] = net.JoinHostPort(n.HostName, strconv.Itoa(n.DERPPort))
			break
		}
	}
	return out
}
