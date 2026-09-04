package core

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"time"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// Relay grants (R0′) — the coordinator's half.
//
// A relay cannot ask the control plane anything: calabi-derp forwards opaque
// ciphertext and has zero control-plane dependencies, which is exactly why it
// can be handed to users to run. So authorization has to travel WITH the node:
// the coordinator signs a short-lived statement, ships it in the netmap, and the
// node presents it when it connects. The relay verifies it offline against the
// coordinator's public key.
//
// Two things the grant is NOT:
//
//   - It is not proof of identity. It is a static blob, so anyone who sees one
//     could replay it; the relay always pairs it with a challenge that proves
//     possession of the node's private key (pkg/mesh-proto/derpauth.go).
//   - It is not a capability the node can extend. The expiry is inside the
//     signature, so "keep using the relay" requires the coordinator to keep
//     saying so.

const (
	// RelayGrantTTL is how long an issued grant stays valid. Short enough that
	// withdrawing authorization takes effect within the hour, long enough that a
	// node briefly out of contact with the coordinator doesn't lose its relay.
	RelayGrantTTL = time.Hour
	// RelayGrantRefresh is how often a node's netmap must be re-sent so its grant
	// never lapses. Comfortably under RelayGrantTTL on purpose: a node's grant is
	// then at most this old, so it always has well over the relay's
	// re-authentication lead time left on it, and a missed refresh is a retry
	// rather than an outage.
	RelayGrantRefresh = 15 * time.Minute
)

// RelayGrantIssuer mints the relay authorization carried in a node's netmap.
// Optional: a coordinator without one issues no grants, which is correct as long
// as its relays don't require them (the state every deployment is in until the
// fleet has upgraded).
type RelayGrantIssuer interface {
	IssueRelayGrant(ctx context.Context, node *Node) ([]byte, error)
}

// SigningRelayGrantIssuer signs grants with the coordinator's key.
type SigningRelayGrantIssuer struct {
	// Key is the coordinator's Ed25519 private key. Its PUBLIC half is what every
	// relay is configured with.
	Key ed25519.PrivateKey
	// Scope decides what a node's grant permits. Nil means RelayScopeAll.
	//
	// This is the seam quota enforcement plugs into (F2): an org over its monthly
	// traffic cap gets RelayScopeSelfHosted, which platform relays refuse and the
	// org's own relays still accept. Downgrading the scope rather than withholding
	// the grant is deliberate — it is what keeps the org's own bandwidth its own
	// business.
	Scope func(ctx context.Context, node *Node) meshproto.RelayScope
	// TTL overrides RelayGrantTTL (tests).
	TTL time.Duration
	// Now is a clock seam for tests.
	Now func() time.Time
}

func (s *SigningRelayGrantIssuer) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *SigningRelayGrantIssuer) ttl() time.Duration {
	if s.TTL > 0 {
		return s.TTL
	}
	return RelayGrantTTL
}

// IssueRelayGrant signs a grant for one node.
func (s *SigningRelayGrantIssuer) IssueRelayGrant(ctx context.Context, node *Node) ([]byte, error) {
	if len(s.Key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("core: relay grant issuer has no signing key")
	}
	scope := meshproto.RelayScopeAll
	if s.Scope != nil {
		scope = s.Scope(ctx, node)
	}
	return meshproto.SignRelayGrant(s.Key, meshproto.RelayGrant{
		Node:    node.NodeKey,
		Meshnet: int64(node.Meshnet),
		Scope:   scope,
		Expiry:  s.now().Add(s.ttl()),
	})
}

// relayGrantFor issues a node's grant, or returns nil when this coordinator
// doesn't issue them. A failure is deliberately NOT fatal to the netmap: losing
// the relay fallback degrades a node, but failing to compute its netmap would
// cut it off from its peers entirely — including the direct paths a relay has
// nothing to do with.
func (c *Coordinator) relayGrantFor(ctx context.Context, node *Node) []byte {
	if c.RelayGrants == nil {
		return nil
	}
	g, err := c.RelayGrants.IssueRelayGrant(ctx, node)
	if err != nil {
		if c.Logger != nil {
			c.Logger.Warn("core: could not issue relay grant", "node_id", node.ID, "err", err)
		}
		return nil
	}
	return g
}
