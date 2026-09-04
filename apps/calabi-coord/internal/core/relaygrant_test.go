package core

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

func signingIssuer(t *testing.T) (*SigningRelayGrantIssuer, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &SigningRelayGrantIssuer{Key: priv}, pub
}

// The netmap is how a grant reaches the node, and the grant has to name that
// node: a relay checks the key in the grant against the key the connection
// claims, so a grant made out to the wrong node is worse than none.
func TestNetMapCarriesAVerifiableGrant(t *testing.T) {
	c := newTestCoord()
	issuer, pub := signingIssuer(t)
	c.RelayGrants = issuer
	ctx := context.Background()

	n, err := c.Register(ctx, RegisterInput{Meshnet: 7, Name: "laptop", NodeKey: key(1)})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nm, err := c.NetMapFor(ctx, n.ID)
	if err != nil {
		t.Fatalf("netmap: %v", err)
	}
	g, err := meshproto.VerifyRelayGrant(pub, nm.RelayGrant, time.Now())
	if err != nil {
		t.Fatalf("verify grant: %v", err)
	}
	if !g.Node.Equal(key(1)) {
		t.Error("grant does not name the node it was issued to")
	}
	if g.Meshnet != 7 {
		t.Errorf("grant meshnet = %d, want 7", g.Meshnet)
	}
	if g.Scope != meshproto.RelayScopeAll {
		t.Errorf("default scope = %v, want all", g.Scope)
	}
	if !g.Expiry.After(time.Now()) {
		t.Error("grant is already expired")
	}
}

// The seam quota enforcement (F2) will plug into: an org over its traffic cap
// gets a scope platform relays refuse while its own relays still accept it.
func TestScopeHookDowngradesTheGrant(t *testing.T) {
	c := newTestCoord()
	issuer, pub := signingIssuer(t)
	issuer.Scope = func(context.Context, *Node) meshproto.RelayScope {
		return meshproto.RelayScopeSelfHosted
	}
	c.RelayGrants = issuer
	ctx := context.Background()

	n, _ := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "laptop", NodeKey: key(1)})
	nm, err := c.NetMapFor(ctx, n.ID)
	if err != nil {
		t.Fatalf("netmap: %v", err)
	}
	g, err := meshproto.VerifyRelayGrant(pub, nm.RelayGrant, time.Now())
	if err != nil {
		t.Fatalf("verify grant: %v", err)
	}
	if g.Scope.Permits(meshproto.RelayKindPlatform) {
		t.Error("a downgraded grant still permits platform relays")
	}
	if !g.Scope.Permits(meshproto.RelayKindSelfHosted) {
		t.Error("a downgraded grant should still permit the org's own relays")
	}
}

// A coordinator that issues no grants must still produce netmaps — that is every
// deployment until its relays are switched to require them.
func TestNetMapWithoutAnIssuerHasNoGrant(t *testing.T) {
	c := newTestCoord()
	ctx := context.Background()
	n, _ := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "laptop", NodeKey: key(1)})
	nm, err := c.NetMapFor(ctx, n.ID)
	if err != nil {
		t.Fatalf("netmap: %v", err)
	}
	if nm.RelayGrant != nil {
		t.Error("a coordinator with no issuer produced a grant")
	}
}

type brokenIssuer struct{}

func (brokenIssuer) IssueRelayGrant(context.Context, *Node) ([]byte, error) {
	return nil, errors.New("signing service is on fire")
}

// Failing to issue a grant costs the node its relay FALLBACK. Failing to build
// the netmap would cost it its peers — including every direct path, which the
// relay has nothing to do with. So the grant degrades and the netmap survives.
func TestNetMapSurvivesAFailedGrant(t *testing.T) {
	c := newTestCoord()
	c.RelayGrants = brokenIssuer{}
	ctx := context.Background()

	n, _ := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "laptop", NodeKey: key(1)})
	peer, _ := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "server", NodeKey: key(2)})

	nm, err := c.NetMapFor(ctx, n.ID)
	if err != nil {
		t.Fatalf("netmap failed because a grant could not be signed: %v", err)
	}
	if nm.RelayGrant != nil {
		t.Error("a failed issuer produced a grant anyway")
	}
	if len(nm.Peers) != 1 || nm.Peers[0].ID != peer.ID {
		t.Errorf("peers lost: got %d", len(nm.Peers))
	}
}

// Expiry is inside the signature, so "keep relaying" needs the coordinator to
// keep saying so. A node holding an old netmap cannot stretch its own grant.
func TestGrantExpiryIsBounded(t *testing.T) {
	c := newTestCoord()
	issuer, pub := signingIssuer(t)
	base := time.Now()
	issuer.Now = func() time.Time { return base }
	c.RelayGrants = issuer
	ctx := context.Background()

	n, _ := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "laptop", NodeKey: key(1)})
	nm, err := c.NetMapFor(ctx, n.ID)
	if err != nil {
		t.Fatalf("netmap: %v", err)
	}
	if _, err := meshproto.VerifyRelayGrant(pub, nm.RelayGrant, base.Add(RelayGrantTTL+time.Minute)); !errors.Is(err, meshproto.ErrGrantExpired) {
		t.Fatalf("grant outlived its TTL (err=%v)", err)
	}
	// And the refresh cadence has to leave room: a node whose netmap is one
	// refresh old must still hold a comfortably valid grant, or the refresh would
	// be racing the expiry.
	if _, err := meshproto.VerifyRelayGrant(pub, nm.RelayGrant, base.Add(RelayGrantRefresh)); err != nil {
		t.Fatalf("grant lapsed within one refresh interval: %v", err)
	}
}
