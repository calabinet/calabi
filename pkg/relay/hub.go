// Package relay is the calabi-derp forwarding core: a key-addressed hub that
// relays already-encrypted mesh packets between connected nodes. It NEVER sees
// plaintext — a SendPacket's payload is WireGuard-encrypted by the sending node,
// so the hub can route by public key but cannot read traffic. This is the
// property that lets the relay be OSS and untrusted. Depends only on pkg/mesh-proto (the public frame contract) + stdlib.
package relay

import (
	"log/slog"
	"net"
	"sync"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// Hub tracks connected clients by node key and forwards packets between them.
type Hub struct {
	mu      sync.RWMutex
	clients map[meshproto.NodeKey]*client
	// usage accumulates relayed bytes per node key (F2, usage.go). Guarded by mu
	// for map access only; the counters themselves are atomic and the forwarding
	// path reaches them through the client, never through this map.
	usage  map[meshproto.NodeKey]*usageCounter
	logger *slog.Logger
	auth   AuthConfig
}

type client struct {
	key  meshproto.NodeKey
	conn net.Conn
	// wmu serializes every write to conn: the control frames written inline below
	// and the data frames written by the queue's own goroutine. Without it the two
	// can interleave mid-frame and desynchronise the stream permanently.
	wmu sync.Mutex
	// sendq carries data frames to this client. Relayed packets go through it so
	// that writing to a slow destination cannot stall the goroutine reading from
	// whoever sent them — see sendq.go.
	sendq  *sendQueue
	closed chan struct{} // closed when Serve returns; stops the writer
	auth   authState     // R0': the challenge/grant state of this link (auth.go)
	usage  *usageCounter
}

// NewHub returns an empty hub. A zero AuthConfig means connections are accepted
// on the node key they claim, with no proof — the pre-R0' behaviour, which is
// still what a relay runs during a staged rollout.
func NewHub(logger *slog.Logger, auth AuthConfig) *Hub {
	return &Hub{clients: make(map[meshproto.NodeKey]*client), logger: logger, auth: auth}
}

func (c *client) write(t meshproto.DERPFrameType, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return meshproto.WriteDERPFrame(c.conn, t, payload)
}

func (h *Hub) add(c *client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	// A node reconnecting (new conn, same key) evicts its stale link.
	if old := h.clients[c.key]; old != nil && old != c {
		_ = old.conn.Close()
	}
	h.clients[c.key] = c
	// The counter outlives the connection: bytes relayed just before a drop still
	// have to be reported, and a reconnect must not restart the tally.
	c.usage = h.counterFor(c.key)
	// Carry the grant's org onto the counter so a platform relay can attribute the
	// bytes it forwards. authenticate() ran on THIS goroutine before add(), so the
	// meshnet is already recorded; a later re-auth updates it in place (auth.go).
	// Zero means auth was off — leave any prior attribution untouched.
	if mn := c.auth.meshnet(); mn != 0 {
		c.usage.meshnet.Store(mn)
	}
}

func (h *Hub) remove(c *client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if cur := h.clients[c.key]; cur == c {
		delete(h.clients, c.key)
	}
}

func (h *Hub) lookup(key meshproto.NodeKey) *client {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.clients[key]
}

// Serve handles one client connection: the mandatory ClientInfo frame, then a
// forward loop until the peer disconnects. It always closes conn on return.
func (h *Hub) Serve(conn net.Conn) {
	defer conn.Close()

	typ, payload, err := meshproto.ReadDERPFrame(conn)
	if err != nil {
		return
	}
	if typ != meshproto.DERPFrameClientInfo || len(payload) != meshproto.KeyLen {
		h.logger.Warn("derp: first frame not a valid ClientInfo; dropping", "type", typ, "len", len(payload))
		return
	}
	var key meshproto.NodeKey
	copy(key[:], payload)
	c := &client{key: key, conn: conn, sendq: newSendQueue(), closed: make(chan struct{})}
	defer close(c.closed)

	// Authenticate BEFORE registering. ClientInfo is only a claim, and add()
	// evicts whatever link currently holds that key — so registering first would
	// hand an unproven connection the power to knock the real node offline for
	// the length of the handshake. See auth.go.
	if h.auth.Require {
		if err := h.authenticate(c); err != nil {
			h.logger.Warn("derp: rejecting unauthenticated connection", "key", key, "err", err)
			return
		}
	}

	h.add(c)
	defer h.remove(c)
	// The writer starts only after add(), so c.usage is set: the queue credits
	// usage itself, on the frames it actually manages to write.
	go c.sendq.run(conn, &c.wmu, c.usage, c.closed)
	h.logger.Info("derp client connected", "key", key)
	defer func() {
		if n := c.sendq.Dropped(); n > 0 {
			h.logger.Info("derp client disconnected", "key", key, "dropped_as_stale", n)
		}
	}()

	for {
		typ, payload, err := meshproto.ReadDERPFrame(conn)
		if err != nil {
			return // EOF / closed / malformed
		}
		switch typ {
		case meshproto.DERPFrameSendPacket:
			dst, ciphertext, err := meshproto.SplitPacket(payload)
			if err != nil {
				continue // ignore malformed packet, keep the link
			}
			// No logging on this line. It ran once per relayed packet with two
			// 32-byte node keys as arguments, which allocates on every packet even
			// when the level is off (the variadic slice and the boxing happen at
			// the call site, before Enabled is consulted) and turns the forwarding
			// core into synchronous log I/O when it is on. What a per-packet log
			// line could tell you, the usage counters and Dropped already do.
			c.usage.in.Add(uint64(len(ciphertext)))
			h.forward(c, dst, ciphertext)
		case meshproto.DERPFramePing:
			_ = c.write(meshproto.DERPFramePong, payload)
		case meshproto.DERPFrameAuthProof:
			// An answer to a re-challenge (Run sends those as a grant nears its
			// expiry). A failure here closes the link: the node held a valid
			// authorization a moment ago and no longer does.
			if !h.auth.Require {
				continue
			}
			if _, err := h.acceptProof(c, payload); err != nil {
				h.logger.Warn("derp: re-authentication failed; closing link", "key", key, "err", err)
				return
			}
		default:
			// Unknown frame types are ignored (forward-compat).
		}
	}
}

// forward relays ciphertext from src to dst as a RecvPacket. Best-effort: if dst
// isn't connected the packet is dropped (the sender upgrades to a direct path or
// retries — MESH.4). The hub treats ciphertext as opaque.
//
// This NEVER blocks. It hands the frame to the destination's own writer and
// returns, so the caller — the source link's read goroutine — keeps reading no
// matter how slow the destination is. See sendq.go for what inline writing here
// cost in the field.
//
// Usage is credited by the writer, not here: a frame that is dropped or fails to
// write cost the platform nothing, and that has to stay true now that dropping
// is something the relay does on purpose.
func (h *Hub) forward(src *client, dst meshproto.NodeKey, ciphertext []byte) {
	dc := h.lookup(dst)
	if dc == nil {
		return // dst offline; nothing to log per packet about it
	}
	if crossesMeshnets(src, dc) {
		return
	}
	frame, err := meshproto.EncodeDERPFrame(meshproto.DERPFrameRecvPacket, meshproto.EncodePacket(src.key, ciphertext))
	if err != nil {
		return // oversize frame: the sender built it, the relay just declines it
	}
	dc.sendq.enqueue(frame, uint64(len(ciphertext)))
}

// crossesMeshnets reports whether a frame would go from one org to another.
// Such a frame is never legitimate - a meshnet is one org and nothing is shared
// between them - and WireGuard on the far side drops it anyway. But by then the
// relay has delivered it, and relay usage is billed as the RECEIVER egress: a
// node of org A could run up the bill of org B with junk addressed to a B node
// key (security audit 1-D). Refusing it here costs two atomic loads a packet.
//
// Only enforceable with authentication on, where each link proved the meshnet
// its grant names. A relay running without it knows no meshnets (both 0) and
// forwards exactly as before; that posture is documented as open.
func crossesMeshnets(src, dst *client) bool {
	// The usage counter mirrors the grant meshnet atomically (add / re-auth), so
	// the per-packet path takes no lock.
	s, d := src.usage.meshnet.Load(), dst.usage.meshnet.Load()
	return s != 0 && d != 0 && s != d
}

// Connected reports whether key currently has a live link (exported for tests
// and, later, the admin endpoint).
func (h *Hub) Connected(key meshproto.NodeKey) bool { return h.lookup(key) != nil }
