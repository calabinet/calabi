package relay

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"time"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// Relay-side authentication (R0′).
//
// What it fixes: without it a connection's identity is whatever node key it
// typed into ClientInfo, and a reconnect with the same key evicts the older
// link. Node keys are public — every peer reads them out of its netmap — so
// anyone who knew one could knock that node off the relay and receive the
// traffic meant for it. Ciphertext stays unreadable, but the denial of service
// and the metadata takeover are real, and they apply to the platform's relays
// exactly as they run today.
//
// The fix keeps the property that makes calabi-derp what it is: it verifies
// everything OFFLINE. A relay holds the coordinator's PUBLIC key as static
// configuration and never opens a connection to the control plane.
//
// Rollout is gated by Require, deliberately, because turning verification on
// disconnects every node that hasn't upgraded yet. Ship with it off, upgrade the
// fleet, then turn it on. (Same lesson as MESH.5b's filter_enabled: an explicit
// flag, never an implicit "empty means...".)

// AuthConfig is a relay's authentication posture. The zero value is "no
// authentication", which is exactly how relays behaved before R0′.
type AuthConfig struct {
	// Require turns verification on. Off: no challenge is ever sent and proofs
	// are ignored, so nodes old and new connect as before.
	Require bool
	// CoordPub is the coordinator's Ed25519 public key, used to verify grants.
	// Required when Require is set.
	CoordPub ed25519.PublicKey
	// Kind is what this relay is. A grant's scope is checked against it, which is
	// how an org over its traffic quota keeps its own relays and loses the
	// platform's.
	Kind meshproto.RelayKind
	// Now is a clock seam for tests; nil means time.Now.
	Now func() time.Time
}

const (
	// handshakeTimeout bounds how long an unauthenticated connection may sit
	// after being challenged. It is NOT registered in the hub during this window,
	// so a stalling attacker cannot displace the real node while it waits.
	handshakeTimeout = 15 * time.Second
	// reauthLead is how far ahead of a grant's expiry the relay asks for a fresh
	// one. Generous on purpose: re-authenticating in place is what keeps a
	// healthy node's link from being dropped and re-dialed every time its grant
	// rolls over.
	reauthLead = 10 * time.Minute
	// reauthTick is the sweep interval, and also the minimum spacing between two
	// challenges to the same client.
	reauthTick = time.Minute
)

// ErrAuthRequired is returned when a connection fails to authenticate.
var ErrAuthRequired = errors.New("relay: connection not authenticated")

// pendingChallenge is one outstanding challenge and the ephemeral private key
// needed to open its answer. It dies with the connection.
type pendingChallenge struct {
	ch      meshproto.DERPAuthChallenge
	ephPriv [meshproto.KeyLen]byte
	sentAt  time.Time
}

// authState is the per-connection half of authentication, embedded in client.
type authState struct {
	mu sync.Mutex
	// grantExpiry is when the grant this link presented runs out. Zero means no
	// grant is on file (authentication disabled, or none presented yet).
	grantExpiry time.Time
	// grantMeshnet is the org the grant attributes this node to. Copied onto the
	// usage counter in add() so a platform relay can bill per org; 0 with auth off.
	grantMeshnet int64
	pending      *pendingChallenge
}

// meshnet returns the org recorded from this link's grant, 0 if none.
func (a *authState) meshnet() int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.grantMeshnet
}

func (h *Hub) now() time.Time {
	if h.auth.Now != nil {
		return h.auth.Now()
	}
	return time.Now()
}

// challenge generates a fresh challenge, records it on the client, and sends it.
// Any previously pending challenge is superseded: only the newest one can be
// answered, so a slow answer to an old one is simply ignored rather than
// accepted late.
func (h *Hub) challenge(c *client) error {
	ch, ephPriv, err := meshproto.NewDERPAuthChallenge()
	if err != nil {
		return err
	}
	c.auth.mu.Lock()
	c.auth.pending = &pendingChallenge{ch: ch, ephPriv: ephPriv, sentAt: h.now()}
	c.auth.mu.Unlock()
	return c.write(meshproto.DERPFrameAuthChallenge, ch.Encode())
}

// acceptProof opens a proof against the outstanding challenge and, if the grant
// checks out, records its expiry.
//
// ok=false with a nil error means there was nothing outstanding to answer — a
// late reply to a challenge already superseded. That is not a failure and must
// not close the link, but it must not count as authentication either, which is
// why this reports acceptance separately from error.
func (h *Hub) acceptProof(c *client, payload []byte) (ok bool, err error) {
	c.auth.mu.Lock()
	p := c.auth.pending
	c.auth.mu.Unlock()
	if p == nil {
		return false, nil
	}
	grant, err := meshproto.OpenDERPAuthProof(p.ch, p.ephPriv, c.key, payload)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrAuthRequired, err)
	}
	g, err := h.checkGrant(c.key, grant)
	if err != nil {
		return false, err
	}
	c.auth.mu.Lock()
	c.auth.grantExpiry, c.auth.grantMeshnet, c.auth.pending = g.Expiry, g.Meshnet, nil
	c.auth.mu.Unlock()
	// On a re-auth of a live link the counter already exists, so refresh its org
	// in place. During the opening handshake c.usage is still nil — add() copies
	// grantMeshnet onto the counter moments later.
	if c.usage != nil {
		c.usage.meshnet.Store(g.Meshnet)
	}
	return true, nil
}

// checkGrant validates a grant blob for the node that presented it. All three
// checks are mandatory and each blocks a different bypass:
//
//   - signature: only the coordinator may authorize a node;
//   - node key: a grant issued to one node must not admit another (otherwise a
//     grant scraped off the wire would be a universal pass);
//   - scope vs this relay's kind: this is what makes quota enforcement bite on
//     platform relays without touching the org's own.
func (h *Hub) checkGrant(claimed meshproto.NodeKey, grant []byte) (meshproto.RelayGrant, error) {
	if len(h.auth.CoordPub) != ed25519.PublicKeySize {
		return meshproto.RelayGrant{}, fmt.Errorf("%w: relay has no coordinator public key configured", ErrAuthRequired)
	}
	g, err := meshproto.VerifyRelayGrant(h.auth.CoordPub, grant, h.now())
	if err != nil {
		return meshproto.RelayGrant{}, fmt.Errorf("%w: %v", ErrAuthRequired, err)
	}
	if !g.Node.Equal(claimed) {
		return meshproto.RelayGrant{}, fmt.Errorf("%w: grant was issued to a different node", ErrAuthRequired)
	}
	if !g.Scope.Permits(h.auth.Kind) {
		return meshproto.RelayGrant{}, fmt.Errorf("%w: grant scope %s does not permit a %s relay", ErrAuthRequired, g.Scope, h.auth.Kind)
	}
	return g, nil
}

// authenticate runs the opening handshake. The client is NOT in the hub while
// this runs — registering first would leave the eviction hole open for the
// duration of the handshake, which is the whole thing we are closing.
//
// Frames that are not the proof are discarded rather than fatal: a node that
// started sending packets before its proof landed is a race, not an attack, and
// the deadline bounds the window either way.
func (h *Hub) authenticate(c *client) error {
	if err := h.challenge(c); err != nil {
		return fmt.Errorf("%w: send challenge: %v", ErrAuthRequired, err)
	}
	if err := c.conn.SetReadDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return fmt.Errorf("%w: set deadline: %v", ErrAuthRequired, err)
	}
	defer func() { _ = c.conn.SetReadDeadline(time.Time{}) }()

	for {
		typ, payload, err := meshproto.ReadDERPFrame(c.conn)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrAuthRequired, err)
		}
		if typ != meshproto.DERPFrameAuthProof {
			continue
		}
		ok, err := h.acceptProof(c, payload)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		// No challenge was outstanding, so this proved nothing. Keep waiting
		// rather than admitting the connection; the deadline ends it.
	}
}

// Run re-authenticates live links until ctx is done. It is what makes a grant's
// expiry mean something: without it a connection established once would outlive
// any authorization it was granted.
//
// The two actions are deliberately different. A grant nearing expiry gets a
// fresh challenge IN PLACE — a healthy node answers with the grant its netmap
// refreshed and nothing is interrupted. A grant that has actually lapsed closes
// the link, which is how an org that lost its authorization stops relaying.
//
// A closed link does not stop the node working: relaying is the fallback path,
// so peers it has a direct path to are unaffected. That distinction is why
// enforcement lives here and not in the DERP map — removing a region would take
// the STUN server with it and break hole punching itself.
func (h *Hub) Run(ctx context.Context) {
	if !h.auth.Require {
		return
	}
	t := time.NewTicker(reauthTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.sweep()
		}
	}
}

func (h *Hub) sweep() {
	now := h.now()
	for _, c := range h.snapshot() {
		c.auth.mu.Lock()
		expiry, pending := c.auth.grantExpiry, c.auth.pending
		c.auth.mu.Unlock()
		if expiry.IsZero() {
			continue
		}
		if now.After(expiry) {
			h.logger.Info("derp: closing link on expired grant", "key", c.key, "expired", expiry)
			_ = c.conn.Close()
			continue
		}
		if !now.After(expiry.Add(-reauthLead)) {
			continue
		}
		if pending != nil && now.Sub(pending.sentAt) < reauthTick {
			continue
		}
		if err := h.challenge(c); err != nil {
			h.logger.Warn("derp: re-challenge failed", "key", c.key, "err", err)
		}
	}
}

// snapshot copies the current client set so the sweep can take its time (and
// close connections) without holding the hub lock.
func (h *Hub) snapshot() []*client {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]*client, 0, len(h.clients))
	for _, c := range h.clients {
		out = append(out, c)
	}
	return out
}
