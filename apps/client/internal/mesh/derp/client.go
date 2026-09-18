// Package derp is the client side of the DERP relay protocol: it dials a relay,
// announces the local node key, and exchanges already-encrypted packets with
// peers by key. It carries opaque ciphertext (the WireGuard datapath encrypts
// before Send and decrypts after onRecv), so the relay never sees plaintext.
// Speaks only pkg/mesh-proto (the public frame contract) + stdlib.
//
// This is the "always-reachable" fallback path of MESH.2 (DERP-only, no hole
// punching yet). MESH.4 adds direct paths and upgrades off the relay.
package derp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/calabi/calabi/apps/client/internal/hostnet"
	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// RecvFunc is invoked for each packet the relay forwards to us, in the read-loop
// goroutine. src is the sending node; ciphertext is opaque (WG-encrypted).
type RecvFunc func(src meshproto.NodeKey, ciphertext []byte)

// Auth is what this node presents when a relay challenges it (R0'). The zero
// value means "nothing to present", which is correct against a relay that
// doesn't require authentication — the pre-R0' behaviour, and what every relay
// runs until the fleet has upgraded.
type Auth struct {
	// Priv is the node's WireGuard private key. Sealing the challenge with it is
	// what proves this connection really is the node key it claimed; ClientInfo
	// on its own is only a claim.
	Priv [meshproto.KeyLen]byte
	// Grant returns the coordinator's current signed authorization, or nil. It is
	// a FUNCTION, not a value, because a relay may re-challenge a live link long
	// after it was dialed: by then the netmap has handed the node a fresher grant
	// and that is the one that must be presented.
	Grant func() []byte
}

// Client is one live link to a relay.
type Client struct {
	self   meshproto.NodeKey
	auth   Auth
	conn   net.Conn
	onRecv RecvFunc
	logger *slog.Logger
	wmu    sync.Mutex // serializes writes that bypass the queue (control frames)
	closed chan struct{}
	// sendq carries DATA frames to a writer goroutine, dropping what has waited
	// too long (sendq.go). Control frames — the auth answer, keepalive pings —
	// still go straight out under wmu: they are rare, they are what keeps the
	// link alive, and they must not be shed when a bulk transfer has filled the
	// queue.
	sendq *sendQueue

	// lastRx is the unix-nano time of the most recent frame from the relay. ANY
	// frame counts, not just a Pong: a link that is carrying packets is alive
	// whether or not a keepalive happens to be in flight.
	//
	// This is the only thing that tells a live link from a half-open one. A
	// successful Send proves nothing — a TCP connection the far side has already
	// forgotten (machine resumed from standby, NAT rebind, relay restarted) keeps
	// accepting writes for as long as the local stack keeps retransmitting, which
	// on Windows is tens of seconds. Silence from the relay is the real signal.
	lastRx atomic.Int64

	// probe is the running leg measurement, or nil. See probe.go for why this
	// rides on Ping/Pong rather than on a second connection.
	probe atomic.Pointer[probeState]

	// sndbuf sizes the kernel send buffer from what this link actually does, or
	// is nil when the policy is not adaptive. See sndbuf.go.
	sndbuf *sndbufCtl

	// pinnedBuf is the size a CALABI_MESH_RELAY_SNDBUF=N override applied, or 0.
	// It exists ONLY so the size stays reportable: without it a pinned link had a
	// nil controller, TxSockBuf answered 0, and `mesh status` printed "kernel
	// auto-tuned (no cap applied)" over a socket that was very much capped — the
	// exact case where someone is trying to find out why the link is slow.
	pinnedBuf int

	// pingAt is the unix-nano time of the keepalive Ping still awaiting a Pong,
	// or 0. It is the ONLY RTT source this link has, and it is deliberately not
	// collected while a leg probe is installed: a probe puts many Pings in flight
	// with no way to match a Pong back to its own, and the mismatch would report
	// a round trip SHORTER than it was. Under-reporting RTT is the one direction
	// the buffer controller cannot tolerate (see sndbuf.go), so a contaminated
	// sample is worth less than no sample.
	pingAt atomic.Int64

	// rttMicros is the most recent keepalive round trip, in microseconds, or 0
	// before the first Pong. It is a LINK measurement — this node to THIS relay —
	// not the end-to-end path to a peer, and whatever displays it has to say so.
	//
	// Stored here rather than only inside the send-buffer controller because that
	// controller is off by default (see sndbuf.go), and its nil check used to drop
	// the sample on the floor: the round trip was measured every 15s and then
	// discarded on every machine running the default configuration.
	rttMicros atomic.Int64
}

// Dial connects to the relay at addr (host:port), announces self via ClientInfo,
// and starts the read loop. onRecv may be nil (drop inbound). The caller owns
// the returned Client and must Close it.
//
// TODO(real-machine slice): wrap the transport in TLS (relay :443) once the
// relay serves it; the payload is already E2E-encrypted so this is defense in
// depth for metadata.
// Dial does NOT wait for a challenge before returning. A relay that doesn't
// require authentication never sends one, and blocking on it would stall every
// dial against the entire un-upgraded fleet. The challenge — whenever it comes,
// at connect time or hours later — is answered from the read loop.
func Dial(ctx context.Context, addr string, self meshproto.NodeKey, auth Auth, onRecv RecvFunc, logger *slog.Logger) (*Client, error) {
	// Through hostnet: the relay link carries the tunnel, so on a phone it must
	// be kept out of the tunnel it carries.
	conn, err := hostnet.Dialer().DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("derp: dial %s: %w", addr, err)
	}
	if err := meshproto.WriteDERPFrame(conn, meshproto.DERPFrameClientInfo, self[:]); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("derp: client info: %w", err)
	}
	// Once per relay connection, not per packet: which send-buffer policy is in
	// force decides whether the queue's deadline can do its job at all, and the
	// field has already cost us two rounds of guessing at it.
	pol := resolveSendBufPolicy(os.Getenv(sendSockBufEnv))
	ctl := applySendBufPolicy(conn, pol)
	if logger != nil && pol.pinned > 0 {
		logger.Info("derp: kernel send buffer pinned", "addr", addr, "bytes", pol.pinned, "env", sendSockBufEnv)
	}
	c := &Client{self: self, auth: auth, conn: conn, onRecv: onRecv, logger: logger,
		closed: make(chan struct{}), sendq: newSendQueue(), sndbuf: ctl, pinnedBuf: pol.pinned}
	c.lastRx.Store(time.Now().UnixNano()) // a fresh link counts as just-heard-from
	go c.readLoop()
	go c.sendq.run(conn, &c.wmu, c.closed, ctl)
	return c, nil
}

// Send relays ciphertext to dst via the relay. Best-effort: the relay drops it
// if dst isn't connected.
// Send is best-effort and NEVER blocks. A frame that cannot be queued, or that
// waits past the queue's deadline, is dropped — see sendq.go for why a relay
// that refuses to drop is the thing that breaks the TCP inside the tunnel.
func (c *Client) Send(dst meshproto.NodeKey, ciphertext []byte) error {
	frame, err := meshproto.EncodeDERPFrame(meshproto.DERPFrameSendPacket, meshproto.EncodePacket(dst, ciphertext))
	if err != nil {
		return err
	}
	c.sendq.enqueue(frame)
	return nil
}

// TxDropped is how many frames this link discarded rather than send late.
func (c *Client) TxDropped() uint64 { return c.sendq.Dropped() }

// TxBlocked is the cumulative time this link's writer spent inside conn.Write —
// the measurement that tells a link which will not take more from a writer that
// simply had nothing to send. See sendq.go.
func (c *Client) TxBlocked() time.Duration { return c.sendq.Blocked() }

// Ping sends an 8-byte keepalive; the relay echoes it as a Pong. The pool sends
// one on a timer so that Idle stays meaningful on a link with no user traffic.
func (c *Client) Ping(payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	// Stamped only when no probe is running, and only when no earlier keepalive
	// is still outstanding: see pingAt. CompareAndSwap rather than Store so a
	// second Ping cannot move the mark and make the first one's Pong look fast.
	if c.probe.Load() == nil {
		c.pingAt.CompareAndSwap(0, time.Now().UnixNano())
	}
	return meshproto.WriteDERPFrame(c.conn, meshproto.DERPFramePing, payload)
}

// observeKeepalivePong closes the round trip opened by Ping and feeds it to the
// send-buffer controller. A Pong with no outstanding keepalive (a probe's, or a
// duplicate) is ignored rather than timed from nothing.
func (c *Client) observeKeepalivePong() {
	sent := c.pingAt.Swap(0)
	if sent == 0 {
		return
	}
	rtt := time.Since(time.Unix(0, sent))
	// Record it FIRST, and unconditionally. The controller is an optional consumer
	// of this number, not its owner — bundling the two meant turning the
	// controller off also turned the measurement off.
	c.rttMicros.Store(rtt.Microseconds())
	if c.sndbuf != nil {
		c.sndbuf.observeRTT(rtt)
	}
}

// RTT is the last measured round trip to THIS relay, or 0 if none yet. One leg:
// this node to the relay, not this node to a peer through it.
func (c *Client) RTT() time.Duration {
	return time.Duration(c.rttMicros.Load()) * time.Microsecond
}

// TxSockBuf is the kernel send-buffer size this link is currently asking for, or
// 0 when the socket has been left to the kernel's own auto-tuning.
func (c *Client) TxSockBuf() int {
	if c.pinnedBuf > 0 {
		return c.pinnedBuf
	}
	if c.sndbuf == nil {
		return 0
	}
	return c.sndbuf.Applied()
}

// TxRate is the windowed-maximum send rate this link has measured, in bytes per
// second, or 0 before it has a sample.
func (c *Client) TxRate() float64 {
	if c.sndbuf == nil {
		return 0
	}
	return c.sndbuf.Rate()
}

// Idle is how long it has been since the relay last said anything on this link.
// The pool tears down a link that stays idle past its deadline even while writes
// to it keep succeeding — see lastRx.
func (c *Client) Idle() time.Duration {
	return time.Since(time.Unix(0, c.lastRx.Load()))
}

// Close tears down the link. The read loop exits on the resulting read error.
func (c *Client) Close() error { return c.conn.Close() }

// Done is closed when the read loop has exited (link dead).
func (c *Client) Done() <-chan struct{} { return c.closed }

// answerChallenge proves possession of the node key and presents whatever grant
// the node holds right now (R0'). A node with no private key configured stays
// silent rather than sending a proof that cannot verify — the relay closes the
// link either way, and silence leaves a clearer trail.
func (c *Client) answerChallenge(payload []byte) error {
	if c.auth.Priv == ([meshproto.KeyLen]byte{}) {
		return errors.New("relay asked for authentication but this link has no node key")
	}
	ch, err := meshproto.ParseDERPAuthChallenge(payload)
	if err != nil {
		return err
	}
	var grant []byte
	if c.auth.Grant != nil {
		grant = c.auth.Grant()
	}
	proof, err := meshproto.SealDERPAuthProof(ch, c.self, c.auth.Priv, grant)
	if err != nil {
		return err
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return meshproto.WriteDERPFrame(c.conn, meshproto.DERPFrameAuthProof, proof)
}

func (c *Client) readLoop() {
	defer close(c.closed)
	for {
		typ, payload, err := meshproto.ReadDERPFrame(c.conn)
		if err != nil {
			return // closed / EOF
		}
		c.lastRx.Store(time.Now().UnixNano())
		switch typ {
		case meshproto.DERPFrameRecvPacket:
			src, ciphertext, err := meshproto.SplitPacket(payload)
			if err != nil {
				continue
			}
			if c.onRecv != nil {
				c.onRecv(src, ciphertext)
			}
		case meshproto.DERPFramePong:
			// Keepalive ack. It also carries a running leg probe's samples when one
			// is installed (probe.go); with none, this is a single atomic load.
			c.observePong(payload)
			c.observeKeepalivePong()
		case meshproto.DERPFrameAuthChallenge:
			if err := c.answerChallenge(payload); err != nil {
				// Not fatal here: the relay decides what an unanswered challenge
				// costs (it closes the link), and saying so once in the log is more
				// use than tearing down from this side.
				c.logger.Warn("mesh: could not answer relay challenge", "err", err)
			}
		default:
			// ignore unknown frames (forward-compat)
		}
	}
}
