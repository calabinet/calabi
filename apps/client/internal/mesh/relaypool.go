package mesh

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/calabinet/calabi/apps/client/internal/mesh/derp"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
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
	// txDroppedGone carries the drop tally of links that have been reaped, so the
	// total never goes down when a link is re-dialed.
	txDroppedGone uint64
	// txBlockedGone does the same for the writers' blocked time.
	txBlockedGone time.Duration
	// refusals holds, per relay address, a relay that has been turning this device
	// away, so the lazy dial paths sit out a growing hold instead of re-dialing it
	// every sweep. See relayHungUp.
	refusals map[string]*relayRefusal
	// onLinkUp, when set, is told each time a link comes up. The bind holds the
	// packets it could not send for want of one (meshBind.hold) and sends them
	// then.
	onLinkUp func(addr string)
}

// errNoRelayLink is Send's answer when no relay link can take the packet yet:
// the home link is still being dialed, held off after a refusal, or there is no
// home relay at all. It used to be net.ErrClosed, which nothing had done and
// which WireGuard printed as "use of closed network connection" at the start of
// every self-hosted device, whose home relay comes with the first netmap.
var errNoRelayLink = errors.New("mesh: no relay link is up yet")

// relayRefusal is what the pool remembers about a relay that keeps turning this
// device away. Dropped once that relay answers a keepalive again.
type relayRefusal struct {
	times int       // consecutive refusals
	until time.Time // lazy dials to this relay wait until then
	grant []byte    // the grant it turned away most recently
	// grants counts the DIFFERENT grants it has turned away in this run. One means
	// only the grant the device had when the refusals began has been tried; more
	// means a newer grant was refused as well. See worthTrying.
	grants int
}

// worthTrying reports whether grant g might get a different answer from this
// relay than the grant it last refused, and so deserves a dial without waiting
// out the hold.
//
// The coordinator signs a fresh grant into every netmap it sends: at least every
// 15 minutes, and on every change in the mesh. A device that has just got its
// coordinator back needs its first fresh grant tried at once — not after minutes
// of a hold its lapsed grant earned. But a relay refusing the device for a reason
// a fresh grant doesn't change (a scope that doesn't cover that relay) would,
// under a rule of "any new grant", be re-dialed as often as netmaps arrive. So:
// while the relay has refused only one grant, any other grant is worth a try;
// once it has refused a newer one as well, only a grant with different terms is.
func (r *relayRefusal) worthTrying(g []byte) bool {
	if bytes.Equal(g, r.grant) {
		return false
	}
	return r.grants <= 1 || !sameGrantTerms(r.grant, g)
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
	// relayRefusalMaxHold caps the hold on a relay that keeps refusing this
	// device, in keepalive intervals: 15s, 30s, 1m, 2m, 4m, then every 5m for as
	// long as the refusals last. Capped, never stopped — a failure that could heal
	// on its own is asked about less often, not given up on.
	relayRefusalMaxHold = 20
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
		refusals:  make(map[string]*relayRefusal),
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
// to be listening on even while it is sending nothing itself. (Unless the home
// relay has been refusing this device: then the re-dial waits out its hold.)
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
	var answered map[string]*derp.Client // links that may end a refusal; only tracked while there is one
	if len(p.refusals) > 0 {
		answered = make(map[string]*derp.Client)
	}
	p.mu.Unlock()

	for addr, c := range links {
		switch {
		case linkDone(c):
			p.relayHungUp(addr, c)
		case c.Idle() > p.deadAfter:
			p.reap(addr, c, "no frame from the relay within the deadline")
		default:
			if err := c.Ping(relayKeepalivePing); err != nil {
				p.reap(addr, c, "keepalive write failed")
			} else if answered != nil && c.RTT() > 0 {
				answered[addr] = c
			}
		}
	}

	p.mu.Lock()
	// A relay that has answered a keepalive has let this device in: it only
	// starts forwarding (Pong included) once the device has authenticated. That,
	// not a link merely staying open, is what ends a run of refusals.
	type readmission struct {
		addr     string
		refusals int
	}
	var readmitted []readmission
	for addr, c := range answered {
		if r := p.refusals[addr]; r != nil && p.clients[addr] == c {
			delete(p.refusals, addr)
			readmitted = append(readmitted, readmission{addr, r.times})
		}
	}
	redial := home != "" && !p.closed && p.clients[home] == nil
	p.mu.Unlock()
	if p.logger != nil {
		for _, r := range readmitted {
			p.logger.Info("mesh: relay accepted this device again", "relay", r.addr, "after_refusals", r.refusals)
		}
	}
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
//
// For the same reason the home re-dial here ignores a refusal hold (relayHungUp):
// a resume or a network change always gets its immediate attempt. If the relay
// still refuses, the hold carries on from where it was.
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
		p.dialNow(home)
	}
}

// SetGrant records the coordinator's latest relay authorization, taken from the
// netmap. Links read it lazily (derp.Auth.Grant is a function) so a relay that
// re-challenges an hours-old link gets the CURRENT grant, not the one that link
// was dialed with.
//
// A new grant also ends the hold on a relay that has been refusing this device,
// if it stands a chance there (worthTrying), and the home relay is then re-dialed
// on the spot.
func (p *relayPool) SetGrant(g []byte) {
	p.mu.Lock()
	if bytes.Equal(g, p.grant) {
		p.mu.Unlock()
		return
	}
	p.grant = g
	redialHome := false
	for addr, r := range p.refusals {
		if !r.worthTrying(g) {
			continue
		}
		r.until = time.Time{}
		if addr == p.home && p.clients[addr] == nil {
			redialHome = true
		}
	}
	home := p.home
	p.mu.Unlock()
	if redialHome {
		p.dial(home)
	}
}

// sameGrantTerms reports whether two grants say the same thing apart from their
// expiry: same node, org and scope. Parsed without verifying — nothing here is an
// access decision, only a guess at whether a relay's answer could change. Two
// blobs that don't parse count as the same (there is nothing to tell them apart
// by); one that parses and one that doesn't, as different.
func sameGrantTerms(a, b []byte) bool {
	ga, errA := meshproto.ParseRelayGrant(a)
	gb, errB := meshproto.ParseRelayGrant(b)
	if errA != nil || errB != nil {
		return errA != nil && errB != nil
	}
	return ga.Node.Equal(gb.Node) && ga.Meshnet == gb.Meshnet && ga.Scope == gb.Scope
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
	p.clients[addr] = c
	p.home = addr
	p.mu.Unlock()
	go p.whenAdmitted(addr, c)
	return nil
}

// whenAdmitted waits for the relay to admit a new link (derp.Client.Ready), then
// says so and tells onLinkUp. Until then clientFor does not send on it: a relay
// that authenticates discards what arrives before the proof.
func (p *relayPool) whenAdmitted(addr string, c *derp.Client) {
	select {
	case <-c.Ready():
	case <-c.Done():
		return
	}
	p.mu.Lock()
	current := p.clients[addr] == c
	up := p.onLinkUp
	p.mu.Unlock()
	if !current {
		return
	}
	if p.logger != nil {
		p.logger.Info("mesh relay link up", "relay", addr)
	}
	if up != nil {
		up(addr)
	}
}

// setOnLinkUp registers the callback told of every link that comes up.
func (p *relayPool) setOnLinkUp(f func(addr string)) {
	p.mu.Lock()
	p.onLinkUp = f
	p.mu.Unlock()
}

// Send relays one packet to dst via the relay at addr — the peer's home relay.
// An empty addr (peer with no known home, or a region missing from the map)
// means the node's own home relay, which is the pre-fleet behaviour. If the
// requested link isn't up yet it is dialed in the background and this packet
// falls back to the home link rather than blocking.
func (p *relayPool) Send(addr string, dst meshproto.NodeKey, ciphertext []byte) error {
	c, use := p.clientFor(addr)
	if c == nil {
		p.mu.Lock()
		closed := p.closed
		p.mu.Unlock()
		if closed {
			return net.ErrClosed
		}
		return errNoRelayLink
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
	c := p.clients[addr]
	if c != nil && c.IsReady() {
		p.mu.Unlock()
		return c, addr
	}
	home := p.home
	hc := p.clients[home]
	p.mu.Unlock()

	if c == nil {
		p.dial(addr) // background; this packet takes the home link
	}
	// A link the relay has not admitted yet carries nothing (see whenAdmitted):
	// the send is held until it is, rather than lost.
	if hc != nil && !hc.IsReady() {
		hc = nil
	}
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
	removed := p.removeLocked(addr, c)
	p.mu.Unlock()
	if removed {
		_ = c.Close()
		if p.logger != nil {
			p.logger.Warn("mesh: relay link dropped; will re-dial", "relay", addr, "reason", reason)
		}
	}
}

// removeLocked takes c out of the pool if it is still the link for addr. False
// means a newer dial has already replaced it. Caller holds p.mu.
func (p *relayPool) removeLocked(addr string, c *derp.Client) bool {
	if p.clients[addr] != c {
		return false
	}
	// Carry the link's drop tally forward before losing the handle to it, or the
	// reported total drops back to whatever the replacement link has sent.
	p.txDroppedGone += c.TxDropped()
	p.txBlockedGone += c.TxBlocked()
	delete(p.clients, addr)
	return true
}

// relayHungUp handles a link the relay itself closed.
//
// Usually that is an ordinary disconnect — a relay restarting, or dropping an
// hours-old link whose grant has run out — and the link is re-dialed at once.
// But a relay that challenged the link and hung up before it had lived one
// keepalive interval has refused this device: the grant it was shown has expired
// (the device was deleted on the coordinator, or has been cut off from it for
// over an hour), or doesn't cover that relay. Re-dialing every sweep changes
// nothing, and costs the relay a connection and a WARN every 15 seconds for as
// long as the device runs. So the relay is held off for a growing interval
// (refusalHold) and asked again when the hold runs out or a new grant arrives
// (SetGrant).
//
// The call rests on what the relay did, not on this machine's reading of the
// grant's expiry: a device whose clock is off would read a live grant as dead,
// or a dead one as live. The expiry only goes into the log.
//
// A hang-up with no challenge is not a refusal. That is a relay — or a TCP proxy
// in front of one — closing connections while it restarts, and holding off there
// would slow down the very recovery the sweep and ResetLinks exist to make fast.
func (p *relayPool) relayHungUp(addr string, c *derp.Client) {
	grant, challenged := c.Challenged()
	if !challenged || c.Lifetime() >= p.pingEvery {
		p.reap(addr, c, "relay closed the link")
		return
	}
	p.mu.Lock()
	if !p.removeLocked(addr, c) {
		p.mu.Unlock()
		return
	}
	r := p.refusals[addr]
	switch {
	case r == nil:
		r = &relayRefusal{grants: 1}
		p.refusals[addr] = r
	case !bytes.Equal(grant, r.grant):
		r.grants++
	}
	r.times++
	r.grant = grant
	hold := p.refusalHold(r.times)
	r.until = time.Now().Add(hold)
	// A netmap may have landed while this link was being turned away, leaving the
	// device with a newer grant than the one refused. If that one stands a chance
	// here, the sweep re-dials with it straight away.
	retryNow := r.worthTrying(p.grant)
	if retryNow {
		r.until = time.Time{}
	}
	times := r.times
	p.mu.Unlock()
	_ = c.Close()
	if p.logger == nil {
		return
	}
	if retryNow {
		p.logger.Info("mesh: relay turned away a grant this device has since replaced; re-dialing with the current one",
			"relay", addr, "refusals", times)
		return
	}
	args := []any{"relay", addr, "refusals", times, "retry_in", hold.String()}
	if g, err := meshproto.ParseRelayGrant(grant); err == nil {
		args = append(args, "grant_expires", g.Expiry.Format(time.RFC3339))
	}
	p.logger.Warn("mesh: relay turned this device away; holding off before re-dialing", args...)
}

// refusalHold is how long lazy dials wait after the n-th refusal in a row: one
// keepalive interval, doubling, capped at relayRefusalMaxHold intervals.
func (p *relayPool) refusalHold(n int) time.Duration {
	hold, most := p.pingEvery, p.pingEvery*relayRefusalMaxHold
	for i := 1; i < n && hold < most; i++ {
		hold *= 2
	}
	return min(hold, most)
}

// heldLocked reports whether lazy dials to addr are still sitting out a refusal
// hold. The last half interval is let off: the sweep that re-dials home runs on a
// pingEvery grid, and a hold that ran out a hair after a tick would otherwise
// cost a whole extra interval. Caller holds p.mu.
func (p *relayPool) heldLocked(addr string) bool {
	r := p.refusals[addr]
	return r != nil && time.Until(r.until) > p.pingEvery/2
}

// dial opens a link in the background (idempotent per address). A failure is
// logged, not retried on a timer: the next send through that relay tries again.
//
// A relay that is refusing this device is not dialed until its hold runs out —
// whoever asks, the sweep, a send or a netmap. A plain dial failure (connection
// refused while a relay restarts) never starts a hold: the relay has said nothing
// about this device, and the retry costs it nothing.
func (p *relayPool) dial(addr string) { p.startDial(addr, false) }

// dialNow is dial past any refusal hold. Only ResetLinks uses it.
func (p *relayPool) dialNow(addr string) { p.startDial(addr, true) }

func (p *relayPool) startDial(addr string, pastHold bool) {
	if addr == "" {
		return
	}
	p.mu.Lock()
	if p.closed || p.clients[addr] != nil || p.dialing[addr] || (!pastHold && p.heldLocked(addr)) {
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
		p.whenAdmitted(addr, c)
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
//
// A node that has no home yet — it started without a relay address, and this is
// the first netmap — takes addr at once, the way DialHome records its address
// before the dial succeeds: there is no previous link to keep traffic on, and
// until p.home is set nothing re-dials it (the sweep, a resume, the send path
// all go by p.home).
func (p *relayPool) setHome(addr string) {
	p.mu.Lock()
	if p.closed || p.home == addr {
		p.mu.Unlock()
		return
	}
	if p.home == "" {
		p.home = addr
		p.mu.Unlock()
		if p.logger != nil {
			p.logger.Info("mesh home relay taken from the coordinator's relay map", "relay", addr)
		}
		p.dial(addr)
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
// TxDropped is how many frames the relay links discarded rather than send late
// (see derp/sendq.go). Summed across live links, plus the tally carried over
// from links that have been reaped — a counter that resets when a link is
// re-dialed would walk backwards, which is exactly the failure the socket
// counters already had once.
func (p *relayPool) TxDropped() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := p.txDroppedGone
	for _, c := range p.clients {
		n += c.TxDropped()
	}
	return n
}

// TxBlocked is the total time the relay writers have spent inside conn.Write,
// summed the same way and for the same reason. Read against the wall clock of a
// transfer it says whether the link refused to take more (blocked ~ the whole
// time) or whether the writer was idle while frames were dropped — which would
// put the throttle somewhere else entirely. See derp/sendq.go.
func (p *relayPool) TxBlocked() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	d := p.txBlockedGone
	for _, c := range p.clients {
		d += c.TxBlocked()
	}
	return d
}

// TxSockBuf and TxRate report the adaptive send-buffer controller's current
// state across the pool's links (derp/sndbuf.go).
//
// These are GAUGES, not counters, and that changes the arithmetic in two ways
// against TxDropped/TxBlocked directly above:
//
//   - They are not summed. Two links each holding a 512 KB buffer are not one
//     link holding 1 MB, and the figure a reader wants is "how much queue is
//     behind the leg carrying my traffic".
//   - There is no carry-over for departed links. A counter has to survive a
//     reconnect or the total goes backwards; a gauge for a link that no longer
//     exists is not a fact about now, and reporting it would keep a stale size
//     on screen long after the socket it described was closed.
//
// The maximum is taken because in the normal case there is exactly one live
// link, where max is simply that link, and where there are several it names the
// one doing the most work rather than averaging it away.
func (p *relayPool) TxSockBuf() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	var n int
	for _, c := range p.clients {
		if v := c.TxSockBuf(); v > n {
			n = v
		}
	}
	return n
}

// TxRate is the windowed-maximum send rate across the pool's links, in bytes per
// second. See TxSockBuf for why it is a maximum and not a sum.
func (p *relayPool) TxRate() float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	var r float64
	for _, c := range p.clients {
		if v := c.TxRate(); v > r {
			r = v
		}
	}
	return r
}

func (p *relayPool) Home() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.home
}

// RTTTo reports the last keepalive round trip to the relay at addr, and whether
// there is one. Keyed by ADDRESS rather than just answering for home, because in
// a fleet a relayed peer can ride a relay that is not this node's home — and the
// number shown next to that peer has to be the leg that actually carries it.
//
// Note what this is NOT: it is one leg (this node to that relay), never the
// end-to-end path to the peer. Every caller that renders it has to say so, or it
// reads as comparable to the direct path's RTT, which it is not.
func (p *relayPool) RTTTo(addr string) (time.Duration, bool) {
	p.mu.Lock()
	c := p.clients[addr]
	p.mu.Unlock()
	if c == nil {
		return 0, false
	}
	rtt := c.RTT()
	return rtt, rtt > 0
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
