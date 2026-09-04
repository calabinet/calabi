package mesh

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
	"github.com/calabi/calabi/pkg/mesh-proto/stun"
)

// magicSock is the node's direct-path UDP socket plus its DISCO identity — the
// heart of hole punching (MESH.4). ONE dual-stack ephemeral port carries all
// three protocols, which is what makes a punched path usable: the NAT binding a
// STUN/DISCO probe opens is the same binding WireGuard data then flows through.
// The read loop demultiplexes them — STUN responses to the reflexive probe,
// DISCO to the probe engine, everything else to the WireGuard bind.
type magicSock struct {
	conn   *net.UDPConn
	port   uint16
	disco  DiscoPrivateKey // authenticates the DISCO exchange (never the traffic key)
	logger *slog.Logger

	mu       sync.Mutex
	closed   bool
	stunWait map[stun.TxID]chan netip.AddrPort // in-flight reflexive probes
	onPong   func(peer meshproto.DiscoKey, tx discoTxID, from netip.AddrPort)
	// onSrc is told the source address of every authenticated DISCO packet, so the
	// bind can attribute later WireGuard packets from that address to the peer.
	onSrc func(peer meshproto.DiscoKey, from netip.AddrPort)
	// onWG receives inbound WireGuard packets (the bind's direct-path inbox). nil
	// until the bind attaches — before that, direct WG packets are dropped and the
	// relay carries everything.
	onWG func(from netip.AddrPort, pkt []byte)
}

// stunProbeTimeout bounds one reflexive-address lookup; the periodic endpoint
// report retries, so a single lost STUN exchange isn't fatal.
const stunProbeTimeout = 2 * time.Second

// newMagicSock opens the direct-path UDP socket and starts its receive loop. The
// port is ephemeral and stable for the session; Endpoints() advertises it, and
// both the probe engine and the WireGuard transport reuse this exact socket, so a
// peer that reaches the advertised address hits our DISCO handler and its data
// lands in the same NAT binding.
func newMagicSock(disco DiscoPrivateKey, logger *slog.Logger) (*magicSock, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0}) // dual-stack, ephemeral
	if err != nil {
		return nil, fmt.Errorf("mesh: open direct-path socket: %w", err)
	}
	la, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("mesh: direct-path socket local addr type %T", conn.LocalAddr())
	}
	m := &magicSock{conn: conn, port: uint16(la.Port), disco: disco, logger: logger,
		stunWait: make(map[stun.TxID]chan netip.AddrPort)}
	go m.readLoop()
	return m, nil
}

// readLoop demultiplexes inbound datagrams on the shared UDP port: STUN responses
// go to the pending reflexive probe, DISCO probes to the hole-punching handler,
// and WireGuard packets to the bind (a peer that punched through to us). Anything
// else is dropped — the port is public, so unsolicited junk arrives.
func (m *magicSock) readLoop() {
	buf := make([]byte, 1500)
	for {
		n, fromUDP, err := m.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return // socket closed
		}
		pkt := buf[:n]
		from := netip.AddrPortFrom(fromUDP.Addr().Unmap(), fromUDP.Port())
		switch {
		case stun.IsSTUN(pkt):
			m.deliverSTUN(pkt)
		case isDisco(pkt):
			m.handleDisco(pkt, from)
		case looksLikeWireGuard(pkt):
			m.deliverWG(from, pkt)
		}
	}
}

// looksLikeWireGuard is the cheap shape check that keeps stray datagrams out of
// the WireGuard receive queue: every WireGuard message starts with a type byte
// (1.4) followed by three reserved zero bytes. It is a filter, not
// authentication — WireGuard itself decides what is genuine.
func looksLikeWireGuard(pkt []byte) bool {
	return len(pkt) >= 4 && pkt[0] >= 1 && pkt[0] <= 4 && pkt[1] == 0 && pkt[2] == 0 && pkt[3] == 0
}

// deliverWG hands an inbound WireGuard packet to the bind. The buffer is reused
// by the read loop, so the handler must copy what it keeps.
func (m *magicSock) deliverWG(from netip.AddrPort, pkt []byte) {
	m.mu.Lock()
	h := m.onWG
	m.mu.Unlock()
	if h != nil {
		h(from, pkt)
	}
}

// handleDisco answers a peer's DISCO ping (so we're reachable at whatever path it
// probed) and routes an authenticated pong to the prober. A packet that fails the
// box (forged / not for us) is dropped by openDisco.
func (m *magicSock) handleDisco(pkt []byte, from netip.AddrPort) {
	sender, msg, ok := openDisco(m.disco, pkt)
	if !ok {
		return
	}
	if m.logger != nil {
		kind := "ping"
		if msg.Type == discoPong {
			kind = "pong"
		}
		m.logger.Debug("mesh disco recv", "kind", kind, "from", from.String())
	}
	// Authenticated: remember where this peer reaches us from. Its WireGuard
	// traffic shares this socket, so it will arrive from the same address.
	m.mu.Lock()
	src := m.onSrc
	m.mu.Unlock()
	if src != nil {
		src(sender, from)
	}
	switch msg.Type {
	case discoPing:
		// Reply with a pong echoing the tx and reporting where we saw the ping —
		// this both confirms the path and tells the pinger its per-peer reflexive
		// address. Send it straight back to the source.
		_ = m.sendDisco(from, sender, discoMessage{Type: discoPong, Tx: msg.Tx, Src: from})
	case discoPong:
		m.mu.Lock()
		h := m.onPong
		m.mu.Unlock()
		if h != nil {
			h(sender, msg.Tx, from)
		}
	}
}

// setPongHandler registers the callback invoked for each authenticated pong.
func (m *magicSock) setPongHandler(h func(meshproto.DiscoKey, discoTxID, netip.AddrPort)) {
	m.mu.Lock()
	m.onPong = h
	m.mu.Unlock()
}

// setSourceHandler registers the callback told where each peer's DISCO traffic
// arrives from.
func (m *magicSock) setSourceHandler(h func(meshproto.DiscoKey, netip.AddrPort)) {
	m.mu.Lock()
	m.onSrc = h
	m.mu.Unlock()
}

// setWGHandler registers the bind's inbox for inbound WireGuard packets.
func (m *magicSock) setWGHandler(h func(netip.AddrPort, []byte)) {
	m.mu.Lock()
	m.onWG = h
	m.mu.Unlock()
}

// WriteTo sends one already-encrypted WireGuard packet straight to a peer's
// validated direct endpoint — the payoff of hole punching: no relay hop. Errors
// (a closed socket, an unreachable network) are the bind's signal to fall back.
func (m *magicSock) WriteTo(pkt []byte, to netip.AddrPort) error {
	if _, err := m.conn.WriteToUDPAddrPort(pkt, to); err != nil {
		return err
	}
	return nil
}

// sendDisco seals a DISCO message to peerDisco and writes it to `to`.
func (m *magicSock) sendDisco(to netip.AddrPort, peerDisco meshproto.DiscoKey, msg discoMessage) error {
	pkt, err := sealDisco(m.disco, peerDisco, msg)
	if err != nil {
		return err
	}
	if _, err := m.conn.WriteToUDPAddrPort(pkt, to); err != nil {
		return err
	}
	return nil
}

// SendPing sends a DISCO ping to a peer's candidate endpoint and returns the tx
// id so the caller can match the pong that validates the path.
func (m *magicSock) SendPing(peerDisco meshproto.DiscoKey, ep netip.AddrPort) (discoTxID, error) {
	tx, err := newDiscoTxID()
	if err != nil {
		return discoTxID{}, err
	}
	return tx, m.sendDisco(ep, peerDisco, discoMessage{Type: discoPing, Tx: tx})
}

// deliverSTUN routes a STUN response to the probe waiting on its transaction id.
func (m *magicSock) deliverSTUN(pkt []byte) {
	tx := stun.TxOf(pkt)
	m.mu.Lock()
	ch := m.stunWait[tx]
	m.mu.Unlock()
	if ch == nil {
		return
	}
	if ap, ok := stun.ParseBindingResponse(pkt, tx); ok {
		select {
		case ch <- ap:
		default:
		}
	}
}

// Reflexive asks a relay's STUN endpoint for the public address it sees this
// socket at — the node's NAT-mapped endpoint, which peers use to reach it across
// NATs (MESH.4). It retransmits until stunProbeTimeout (UDP loses packets) and
// returns the reflexive address or an error. The result shares the socket's port,
// so the advertised endpoint is exactly where our DISCO/WG handler listens.
func (m *magicSock) Reflexive(ctx context.Context, stunServer netip.AddrPort) (netip.AddrPort, error) {
	tx, err := stun.NewTxID()
	if err != nil {
		return netip.AddrPort{}, err
	}
	ch := make(chan netip.AddrPort, 1)
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return netip.AddrPort{}, net.ErrClosed
	}
	m.stunWait[tx] = ch
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.stunWait, tx)
		m.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(ctx, stunProbeTimeout)
	defer cancel()
	req := stun.BindingRequest(tx)
	retransmit := time.NewTicker(300 * time.Millisecond)
	defer retransmit.Stop()
	for {
		if _, err := m.conn.WriteToUDPAddrPort(req, stunServer); err != nil {
			return netip.AddrPort{}, fmt.Errorf("mesh: send STUN to %s: %w", stunServer, err)
		}
		select {
		case <-ctx.Done():
			return netip.AddrPort{}, ctx.Err()
		case ap := <-ch:
			return ap, nil
		case <-retransmit.C:
		}
	}
}

// LocalPort is the UDP port the socket is bound to (the port advertised in every
// candidate endpoint).
func (m *magicSock) LocalPort() uint16 { return m.port }

// Endpoints returns the node's candidate direct endpoints: each usable local
// interface address paired with the socket's port. Best-effort — a discovery
// error yields no endpoints, leaving the node reachable via the relay.
func (m *magicSock) Endpoints() []netip.AddrPort {
	eps, err := localEndpoints(m.port)
	if err != nil {
		if m.logger != nil {
			m.logger.Warn("mesh: enumerate local endpoints failed", "err", err)
		}
		return nil
	}
	return eps
}

// Close releases the UDP socket. Idempotent.
func (m *magicSock) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	return m.conn.Close()
}
