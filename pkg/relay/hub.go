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
	key   meshproto.NodeKey
	conn  net.Conn
	wmu   sync.Mutex // serializes frame writes to conn
	auth  authState  // R0': the challenge/grant state of this link (auth.go)
	usage *usageCounter
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
	c := &client{key: key, conn: conn}

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
	h.logger.Info("derp client connected", "key", key)

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
			h.logger.Debug("derp recv SendPacket", "src", key, "dst", dst, "bytes", len(ciphertext))
			c.usage.in.Add(uint64(len(ciphertext)))
			h.forward(key, dst, ciphertext)
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
func (h *Hub) forward(src, dst meshproto.NodeKey, ciphertext []byte) {
	dc := h.lookup(dst)
	if dc == nil {
		h.logger.Debug("derp forward: dst not connected", "src", src, "dst", dst)
		return
	}
	if err := dc.write(meshproto.DERPFrameRecvPacket, meshproto.EncodePacket(src, ciphertext)); err != nil {
		h.logger.Warn("derp forward failed", "err", err)
		return
	}
	// Counted on success only: a write that failed cost the platform nothing.
	dc.usage.out.Add(uint64(len(ciphertext)))
	h.logger.Debug("derp forwarded", "src", src, "dst", dst, "bytes", len(ciphertext))
}

// Connected reports whether key currently has a live link (exported for tests
// and, later, the admin endpoint).
func (h *Hub) Connected(key meshproto.NodeKey) bool { return h.lookup(key) != nil }
