// Package derp is the client side of the calabi-derp relay: it dials a relay,
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
	"sync"
	"sync/atomic"
	"time"

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
	wmu    sync.Mutex // serializes writes
	closed chan struct{}

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
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("derp: dial %s: %w", addr, err)
	}
	if err := meshproto.WriteDERPFrame(conn, meshproto.DERPFrameClientInfo, self[:]); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("derp: client info: %w", err)
	}
	c := &Client{self: self, auth: auth, conn: conn, onRecv: onRecv, logger: logger, closed: make(chan struct{})}
	c.lastRx.Store(time.Now().UnixNano()) // a fresh link counts as just-heard-from
	go c.readLoop()
	return c, nil
}

// Send relays ciphertext to dst via the relay. Best-effort: the relay drops it
// if dst isn't connected.
func (c *Client) Send(dst meshproto.NodeKey, ciphertext []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return meshproto.WriteDERPFrame(c.conn, meshproto.DERPFrameSendPacket, meshproto.EncodePacket(dst, ciphertext))
}

// Ping sends an 8-byte keepalive; the relay echoes it as a Pong. The pool sends
// one on a timer so that Idle stays meaningful on a link with no user traffic.
func (c *Client) Ping(payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return meshproto.WriteDERPFrame(c.conn, meshproto.DERPFramePing, payload)
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
			// keepalive ack; RTT accounting lands with path selection (MESH.4)
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
