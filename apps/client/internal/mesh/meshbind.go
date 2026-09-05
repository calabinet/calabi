package mesh

import (
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// meshBind is the wireguard-go conn.Bind that carries WireGuard's
// already-encrypted packets to peers over EITHER of two transports:
//
//   - the calabi-derp relay, keyed by peer node key (MESH.2, always available:
//     both nodes hold an outbound connection to the relay, so it works behind any
//     NAT); or
//   - a direct UDP path discovered by DISCO hole punching (MESH.4 B3), when the
//     prober has validated one for that peer.
//
// Send picks per packet: a fresh validated direct path wins, otherwise the relay.
// That decision is re-taken on every send, so a path that goes stale (no pong
// within pathTTL) silently falls back to the relay, and a newly punched one is
// picked up within a probe interval — without touching the WireGuard session.
// Direct is strictly an optimisation layered on a relay that always works.
//
// Inbound is symmetric: relay packets arrive via deliver() from the relay
// client's read loop, direct packets via deliverDirect() from the magic socket's
// read loop. Both land in one queue that the WireGuard receive loop drains.
//
// ⚠ COMPILE-VERIFIED + LOOPBACK-TESTED ONLY. The relay path has a real
// two-machine run behind it; the direct
// path is exercised over loopback sockets in tests but a real NAT traversal needs
// two machines on different networks —
type meshBind struct {
	self   meshproto.NodeKey
	client relaySender // set via attach() before Open
	logger *slog.Logger

	mu     sync.Mutex
	recv   chan inbound  // persistent inbound queue (relay + direct)
	closed chan struct{} // per Open/Close cycle: recreated by Open, closed by Close
	open   bool

	// Direct-path state (MESH.4 B3-3), guarded by dmu. All of it is optional: a
	// bind with no direct transport attached behaves exactly like the relay-only
	// bind that came before it.
	dmu sync.Mutex
	// direct is the shared UDP socket that also carries STUN/DISCO; nil until
	// attachDirect (and again after detachDirect, e.g. a control-plane reconnect).
	direct *magicSock
	// paths reports which direct endpoint (if any) currently reaches a peer.
	paths pathFinder
	// directOff disables direct paths wholesale. Set while a full-tunnel exit node
	// is engaged: the exit routes send everything not explicitly bypassed into the
	// tun, and a peer's public IP is not bypassed — sending WireGuard's own
	// transport there would loop it back through the tun. The relay IS bypassed,
	// so relay-only is the safe transport in that mode.
	directOff bool
	// discoOf/keyOf map a peer's node key to its disco key and back (from each
	// netmap, via setPeers): Send holds a node key and needs the disco key the
	// prober files paths under; deliverDirect holds a disco key and needs the node
	// key WireGuard identifies the peer by.
	discoOf map[meshproto.NodeKey]meshproto.DiscoKey
	keyOf   map[meshproto.DiscoKey]meshproto.NodeKey
	// relayOf maps a peer's node key to the relay address it is homed at (MESH.4
	// B2b), so a relayed packet takes the peer's OWN relay rather than ours — the
	// only relay it is listening on. Empty/absent falls back to our home relay.
	relayOf map[meshproto.NodeKey]string
	// srcOf remembers which peer sent DISCO from which source address, so an
	// inbound direct WireGuard packet can be attributed to a peer (and answered
	// over whichever transport is best at that moment) instead of being pinned to
	// the address it arrived from. Only known peers are recorded, so it stays
	// bounded by the netmap.
	srcOf map[netip.AddrPort]meshproto.DiscoKey
}

// relaySender is the relay transport the bind falls back to — the relayPool in
// production, a recorder in tests. relayAddr names WHICH relay to send through
// (the peer's home relay); "" means this node's own home relay.
type relaySender interface {
	Send(relayAddr string, dst meshproto.NodeKey, ciphertext []byte) error
}

// pathFinder is the DISCO prober's view the bind consumes: which direct endpoint
// currently reaches a peer, and a way to retire one that turns out to be dead.
type pathFinder interface {
	bestPath(peer meshproto.DiscoKey) (netip.AddrPort, bool)
	// pathRTT is the round-trip of that path. Reported, never used to route —
	// Send asks bestPath, which already picked on it.
	pathRTT(peer meshproto.DiscoKey) (time.Duration, bool)
	invalidatePath(peer meshproto.DiscoKey)
	// learnCandidate offers an endpoint a peer's DISCO traffic arrived from as a
	// probe target — the only way to reach a symmetric-NAT peer, whose netmap
	// endpoint (its STUN port) its NAT won't accept our packets on.
	learnCandidate(peer meshproto.DiscoKey, ep netip.AddrPort)
}

// inbound is one received WireGuard packet plus the endpoint WireGuard should
// associate with its peer (see meshEndpoint).
type inbound struct {
	ep  conn.Endpoint
	pkt []byte
}

func newMeshBind(self meshproto.NodeKey, logger *slog.Logger) *meshBind {
	return &meshBind{
		self:   self,
		logger: logger,
		recv:   make(chan inbound, 256),
		closed: make(chan struct{}), // replaced on first Open
	}
}

// attach wires the relay client whose onRecv feeds deliver().
func (b *meshBind) attach(c relaySender) { b.client = c }

// attachDirect wires the direct transport: the shared UDP socket that carries
// DISCO (and now WireGuard) and the prober that validates paths over it. Called
// once the control-plane loop has both; until then — and again after
// detachDirect — every packet takes the relay. Registering the socket handlers
// here (rather than at socket creation) keeps the wiring in one place.
func (b *meshBind) attachDirect(ms *magicSock, paths pathFinder) {
	b.dmu.Lock()
	b.direct = ms
	b.paths = paths
	b.srcOf = make(map[netip.AddrPort]meshproto.DiscoKey) // a new socket ⇒ new source mappings
	b.dmu.Unlock()

	ms.setWGHandler(b.deliverDirect)
	ms.setSourceHandler(b.noteDiscoSource)
}

// detachDirect drops the direct transport (the socket is about to close, e.g. the
// control-plane loop is restarting). Sends fall back to the relay immediately.
func (b *meshBind) detachDirect() {
	b.dmu.Lock()
	b.direct = nil
	b.paths = nil
	b.srcOf = nil
	b.dmu.Unlock()
}

// setDirectEnabled turns direct paths on/off wholesale (see directOff).
func (b *meshBind) setDirectEnabled(on bool) {
	b.dmu.Lock()
	b.directOff = !on
	b.dmu.Unlock()
}

// setPeers refreshes the per-peer routing tables from the netmap-derived config:
// the node-key ⟷ disco-key mapping (which direct path belongs to whom) and each
// peer's home relay (which relay reaches it). Source addresses of peers that are
// no longer in the config are forgotten.
func (b *meshBind) setPeers(cfg WGConfig) {
	discoOf := make(map[meshproto.NodeKey]meshproto.DiscoKey, len(cfg.Peers))
	keyOf := make(map[meshproto.DiscoKey]meshproto.NodeKey, len(cfg.Peers))
	relayOf := make(map[meshproto.NodeKey]string, len(cfg.Peers))
	for _, p := range cfg.Peers {
		if p.PublicKey.IsZero() {
			continue
		}
		if addr := cfg.RelayByRegion[p.DERPHome]; addr != "" {
			relayOf[p.PublicKey] = addr
		}
		if p.DiscoKey.IsZero() {
			continue
		}
		discoOf[p.PublicKey] = p.DiscoKey
		keyOf[p.DiscoKey] = p.PublicKey
	}
	b.dmu.Lock()
	defer b.dmu.Unlock()
	b.discoOf, b.keyOf, b.relayOf = discoOf, keyOf, relayOf
	for ap, dk := range b.srcOf {
		if _, ok := keyOf[dk]; !ok {
			delete(b.srcOf, ap)
		}
	}
}

// relayFor returns the relay address a peer is homed at ("" = use our own home
// relay).
func (b *meshBind) relayFor(key meshproto.NodeKey) string {
	b.dmu.Lock()
	defer b.dmu.Unlock()
	return b.relayOf[key]
}

// noteDiscoSource records that a peer's DISCO traffic reaches us from `from`, so
// its direct WireGuard packets (which share that socket, hence that source
// address) can be attributed to it. Unknown senders are ignored — that keeps the
// table bounded by the netmap, and an unattributed packet still gets delivered
// (see deliverDirect); it just can't roam the peer onto a shared transport.
func (b *meshBind) noteDiscoSource(peer meshproto.DiscoKey, from netip.AddrPort) {
	b.dmu.Lock()
	if b.srcOf == nil {
		b.dmu.Unlock()
		return
	}
	if _, known := b.keyOf[peer]; !known {
		b.dmu.Unlock()
		return
	}
	b.srcOf[from] = peer
	paths := b.paths
	b.dmu.Unlock()
	// Feed the observed source to the prober too: for a symmetric-NAT peer this is
	// its ONLY reachable port (its netmap endpoint is the STUN port), so without
	// probing it the cone side never validates a direct return path and stays on
	// the relay. Released b.dmu first — learnCandidate takes the prober's lock.
	if paths != nil {
		paths.learnCandidate(peer, from)
	}
}

// deliver is called from the relay client's read loop for each inbound packet.
// It copies the ciphertext (the relay client may reuse its buffer) and queues it
// for the WireGuard receive loop; drops when the queue is full.
func (b *meshBind) deliver(src meshproto.NodeKey, ciphertext []byte) {
	b.enqueue(&meshEndpoint{b: b, key: src}, ciphertext)
}

// deliverDirect is called from the magic socket's read loop for each inbound
// packet that is neither STUN nor DISCO — i.e. WireGuard arriving over a punched
// direct path. When the source address is attributable to a peer, the packet is
// handed to WireGuard with that peer's KEYED endpoint, so replies keep choosing
// their transport per send (direct now, relay if the path dies). Otherwise it is
// delivered pinned to the source address, exactly as a plain UDP bind would:
// WireGuard authenticates before it roams a peer, so an unattributable packet
// that isn't genuine is simply dropped a layer up.
func (b *meshBind) deliverDirect(from netip.AddrPort, pkt []byte) {
	ep := &meshEndpoint{b: b, direct: from}
	b.dmu.Lock()
	if dk, ok := b.srcOf[from]; ok {
		if nk, ok := b.keyOf[dk]; ok {
			ep = &meshEndpoint{b: b, key: nk}
		}
	}
	b.dmu.Unlock()
	b.enqueue(ep, pkt)
}

// enqueue copies pkt (both read loops reuse their buffers) and queues it for the
// WireGuard receive loop; drops when the queue is full.
func (b *meshBind) enqueue(ep conn.Endpoint, pkt []byte) {
	b.mu.Lock()
	closed := b.closed
	b.mu.Unlock()
	cp := append([]byte(nil), pkt...)
	select {
	case b.recv <- inbound{ep: ep, pkt: cp}:
	case <-closed:
	default:
		// queue full — drop; WireGuard retransmits.
	}
}

// Open returns the single receive function WireGuard polls. wireguard-go opens
// and closes a bind repeatedly over a device's life (Up/Down, listen-port
// changes, roaming), so each Open starts a FRESH receive cycle with a new
// `closed` channel — otherwise a prior Close would make every re-Opened receive
// return ErrClosed immediately and no inbound packet is ever read.
func (b *meshBind) Open(_ uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = make(chan struct{})
	b.open = true
	return []conn.ReceiveFunc{b.receive}, 0, nil
}

func (b *meshBind) receive(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	b.mu.Lock()
	closed := b.closed
	b.mu.Unlock()
	// Block for at least one packet, then drain up to len(packets) without blocking.
	select {
	case <-closed:
		return 0, net.ErrClosed
	case in := <-b.recv:
		n := 0
		if put(packets, sizes, eps, n, in) {
			n++
		}
		for n < len(packets) {
			select {
			case in := <-b.recv:
				if put(packets, sizes, eps, n, in) {
					n++
				}
			default:
				return n, nil
			}
		}
		return n, nil
	}
}

// put copies one inbound packet into the WireGuard receive buffers. Returns false
// (and skips) if the packet doesn't fit the provided buffer.
func put(packets [][]byte, sizes []int, eps []conn.Endpoint, i int, in inbound) bool {
	if len(in.pkt) > len(packets[i]) {
		return false
	}
	copy(packets[i], in.pkt)
	sizes[i] = len(in.pkt)
	eps[i] = in.ep
	return true
}

// Close ends the current receive cycle (idempotent per cycle). A later Open
// starts a new one; the datapath's own teardown Closes for good.
func (b *meshBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.open {
		close(b.closed)
		b.open = false
	}
	return nil
}

func (b *meshBind) SetMark(uint32) error { return nil }

// Send writes each WireGuard packet to the peer over the best transport it has:
// a validated direct UDP path when one is fresh, otherwise the relay. A direct
// write that fails retires the path (the prober re-validates it within a probe
// interval if it recovers) and the packet still goes out over the relay, so a
// transport hiccup never drops a WireGuard session.
func (b *meshBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	me, ok := ep.(*meshEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	if ms, ap, disco, ok := b.directTarget(me); ok {
		err := sendAllDirect(ms, bufs, ap)
		if err == nil {
			return nil
		}
		if !disco.IsZero() {
			b.retirePath(disco, ap, err)
		}
		if me.key.IsZero() {
			return err // pinned to a direct address: no relay route to fall back to
		}
	}
	if me.key.IsZero() {
		// A pinned endpoint with no direct transport left (it was detached
		// mid-session): there is no node key to relay to. WireGuard re-learns the
		// peer's endpoint from its next relayed packet.
		return net.ErrClosed
	}
	if b.client == nil {
		return net.ErrClosed
	}
	relay := b.relayFor(me.key)
	for _, buf := range bufs {
		if err := b.client.Send(relay, me.key, buf); err != nil {
			return err
		}
	}
	return nil
}

// directTarget resolves the direct endpoint to use for one send, if any: the
// address a pinned endpoint carries, or the peer's currently validated path. The
// returned disco key is the one the path is filed under (zero for a pinned
// endpoint), so a failed write can retire exactly that path.
func (b *meshBind) directTarget(me *meshEndpoint) (*magicSock, netip.AddrPort, meshproto.DiscoKey, bool) {
	b.dmu.Lock()
	defer b.dmu.Unlock()
	if b.direct == nil || b.directOff {
		return nil, netip.AddrPort{}, meshproto.DiscoKey{}, false
	}
	if me.direct.IsValid() {
		return b.direct, me.direct, meshproto.DiscoKey{}, true
	}
	if b.paths == nil {
		return nil, netip.AddrPort{}, meshproto.DiscoKey{}, false
	}
	disco, ok := b.discoOf[me.key]
	if !ok {
		return nil, netip.AddrPort{}, meshproto.DiscoKey{}, false
	}
	ap, ok := b.paths.bestPath(disco)
	if !ok {
		return nil, netip.AddrPort{}, meshproto.DiscoKey{}, false
	}
	return b.direct, ap, disco, true
}

// retirePath drops a validated path whose write just failed, so the next send
// relays instead of retrying a dead socket route.
func (b *meshBind) retirePath(disco meshproto.DiscoKey, ap netip.AddrPort, cause error) {
	b.dmu.Lock()
	paths := b.paths
	b.dmu.Unlock()
	if paths == nil {
		return
	}
	paths.invalidatePath(disco)
	if b.logger != nil {
		b.logger.Info("mesh direct path failed; falling back to relay", "endpoint", ap.String(), "err", cause)
	}
}

// sendAllDirect writes every packet of a batch to one direct endpoint, stopping
// at the first error.
func sendAllDirect(ms *magicSock, bufs [][]byte, to netip.AddrPort) error {
	for _, buf := range bufs {
		if err := ms.WriteTo(buf, to); err != nil {
			return err
		}
	}
	return nil
}

// directPath reports the peer's live direct endpoint, if traffic to it is
// currently taking one. Drives the direct/relay column in `calabi mesh status`
// and the :7400 console, and the endpoint `wg show` prints.
func (b *meshBind) directPath(key meshproto.NodeKey) (netip.AddrPort, bool) {
	_, ap, _, ok := b.directTarget(&meshEndpoint{b: b, key: key})
	return ap, ok
}

// directRTT reports the round-trip of the peer's direct path, for the console.
// Deliberately separate from directPath rather than folded into it: the send path
// calls directPath on every packet and has no use for the number. The pair is
// therefore read non-atomically — a path that changes between the two calls shows
// the new endpoint with the old round-trip for one poll, which is a display
// artefact and nothing more.
func (b *meshBind) directRTT(key meshproto.NodeKey) (time.Duration, bool) {
	b.dmu.Lock()
	paths := b.paths
	disco, ok := b.discoOf[key]
	b.dmu.Unlock()
	if paths == nil || !ok {
		return 0, false
	}
	return paths.pathRTT(disco)
}

// ParseEndpoint decodes the peer node key (base64) the UAPI carries in
// "endpoint=" back into a meshEndpoint. SetConfig always writes the node-key
// form, so the endpoint stays transport-agnostic: Send re-picks direct vs relay
// per packet.
func (b *meshBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	k, err := meshproto.ParseNodeKey(s)
	if err != nil {
		return nil, err
	}
	return &meshEndpoint{b: b, key: k}, nil
}

// BatchSize is 1: neither transport is batched (unlike raw UDP GSO).
func (b *meshBind) BatchSize() int { return 1 }

// meshEndpoint is a conn.Endpoint that names a peer rather than an address: the
// bind reaches it over whichever transport is best at send time. `direct` is set
// only for a packet that arrived over a direct path we couldn't attribute to a
// peer — then the address itself IS the endpoint, as with a plain UDP bind.
type meshEndpoint struct {
	b      *meshBind
	key    meshproto.NodeKey
	direct netip.AddrPort
}

func (e *meshEndpoint) ClearSrc()           {}
func (e *meshEndpoint) SrcToString() string { return "" }

// DstToString returns a wg-parseable host:port. When traffic to this peer is
// taking a direct path, that's the real punched endpoint — which is exactly what
// makes `wg show` useful for confirming hole punching on a real machine. Over the
// relay there is no address to show (the transport is a node key), so we map the
// key into a stable ULA IPv6 (fd00::/8), port 0: `wg show` and wireguard-go's
// UAPI "get" abort the WHOLE readout with EPROTO on an unparseable endpoint, so
// this synthetic address is what keeps a relayed peer visible. Port 0 marks it as
// synthetic.
func (e *meshEndpoint) DstToString() string {
	if ap, ok := e.liveAddr(); ok {
		return ap.String()
	}
	return netip.AddrPortFrom(e.syntheticAddr(), 0).String()
}

// DstIP is what wireguard-go's handshake rate limiter buckets by. A real address
// for a direct path; the per-peer synthetic address otherwise, so one peer's
// handshake flood can't consume another's budget.
func (e *meshEndpoint) DstIP() netip.Addr {
	if ap, ok := e.liveAddr(); ok {
		return ap.Addr()
	}
	return e.syntheticAddr()
}

func (e *meshEndpoint) SrcIP() netip.Addr { return netip.Addr{} }

// liveAddr is the direct address currently carrying this peer's traffic, if any.
func (e *meshEndpoint) liveAddr() (netip.AddrPort, bool) {
	if e.direct.IsValid() {
		return e.direct, true
	}
	if e.b == nil {
		return netip.AddrPort{}, false
	}
	return e.b.directPath(e.key)
}

// syntheticAddr maps the peer node key into a stable ULA IPv6 address — a
// display-only stand-in for "reached via relay".
func (e *meshEndpoint) syntheticAddr() netip.Addr {
	var a [16]byte
	a[0] = 0xfd
	copy(a[1:], e.key[:])
	return netip.AddrFrom16(a)
}

func (e *meshEndpoint) DstToBytes() []byte {
	if e.direct.IsValid() {
		b, _ := e.direct.MarshalBinary()
		return b
	}
	b := e.key
	return b[:]
}
