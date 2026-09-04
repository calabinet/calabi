package relay

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"log/slog"
	"net"
	"testing"
	"time"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// nodeKeys makes a Curve25519 keypair in the shape a mesh node uses. crypto/ecdh
// rather than nacl/box on purpose: this package's dependency surface is part of
// what makes calabi-derp safe to hand to users, so its tests stay on stdlib too.
func nodeKeys(t *testing.T) (meshproto.NodeKey, [meshproto.KeyLen]byte) {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate node key: %v", err)
	}
	var pub meshproto.NodeKey
	copy(pub[:], k.PublicKey().Bytes())
	var priv [meshproto.KeyLen]byte
	copy(priv[:], k.Bytes())
	return pub, priv
}

type coord struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newCoord(t *testing.T) coord {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate coordinator key: %v", err)
	}
	return coord{pub: pub, priv: priv}
}

func (c coord) grant(t *testing.T, node meshproto.NodeKey, scope meshproto.RelayScope, expiry time.Time) []byte {
	t.Helper()
	b, err := meshproto.SignRelayGrant(c.priv, meshproto.RelayGrant{
		Node: node, Meshnet: 1, Scope: scope, Expiry: expiry,
	})
	if err != nil {
		t.Fatalf("sign grant: %v", err)
	}
	return b
}

// handshake runs the node side of the exchange over conn: ClientInfo, then the
// answer to whatever challenge comes back. sealWith is the private key used to
// build the proof — a test passes someone else's to play the impostor.
func handshake(t *testing.T, conn net.Conn, claim meshproto.NodeKey, sealWith [meshproto.KeyLen]byte, grant []byte) error {
	t.Helper()
	if err := meshproto.WriteDERPFrame(conn, meshproto.DERPFrameClientInfo, claim[:]); err != nil {
		return err
	}
	return answerChallenge(t, conn, claim, sealWith, grant)
}

func answerChallenge(t *testing.T, conn net.Conn, claim meshproto.NodeKey, sealWith [meshproto.KeyLen]byte, grant []byte) error {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	typ, payload, err := meshproto.ReadDERPFrame(conn)
	if err != nil {
		return err
	}
	if typ != meshproto.DERPFrameAuthChallenge {
		t.Fatalf("expected a challenge, got frame type %v", typ)
	}
	_ = conn.SetReadDeadline(time.Time{})
	ch, err := meshproto.ParseDERPAuthChallenge(payload)
	if err != nil {
		return err
	}
	proof, err := meshproto.SealDERPAuthProof(ch, claim, sealWith, grant)
	if err != nil {
		return err
	}
	return meshproto.WriteDERPFrame(conn, meshproto.DERPFrameAuthProof, proof)
}

// grantExpiryOf reads back what the relay recorded for a link. Asserting on it
// is deterministic, unlike Connected(): sweep() closes a conn and the client is
// only unregistered once Serve's read fails, so a Connected() check taken right
// after a sweep can still see a link that is already doomed.
func grantExpiryOf(t *testing.T, h *Hub, k meshproto.NodeKey) time.Time {
	t.Helper()
	h.mu.RLock()
	c := h.clients[k]
	h.mu.RUnlock()
	if c == nil {
		t.Fatal("node is not connected")
	}
	c.auth.mu.Lock()
	defer c.auth.mu.Unlock()
	return c.auth.grantExpiry
}

// stillOpen reports whether the relay end of conn is alive: a closed link reads
// an error, a live one just has nothing to say.
func stillOpen(t *testing.T, conn net.Conn) bool {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	_, _, err := meshproto.ReadDERPFrame(conn)
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func connected(h *Hub, k meshproto.NodeKey, want bool) func() bool {
	return func() bool { return h.Connected(k) == want }
}

func eventually(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal(msg)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestAuthenticatedNodeConnects(t *testing.T) {
	c := newCoord(t)
	h := NewHub(slog.Default(), AuthConfig{Require: true, CoordPub: c.pub, Kind: meshproto.RelayKindPlatform})
	nk, priv := nodeKeys(t)

	mine, theirs := net.Pipe()
	t.Cleanup(func() { _ = mine.Close() })
	go h.Serve(theirs)

	if err := handshake(t, mine, nk, priv, c.grant(t, nk, meshproto.RelayScopeAll, time.Now().Add(time.Hour))); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	eventually(t, connected(h, nk, true), "authenticated node was never registered")
}

// THE regression. An attacker knows the victim's node key (every peer does) and
// has even captured the grant the coordinator issued to it. Neither is enough:
// it cannot produce the proof, so it is never registered — and crucially the
// victim's existing link is NOT evicted, because registration happens only after
// authentication succeeds.
func TestImpostorCannotEvictTheRealNode(t *testing.T) {
	c := newCoord(t)
	h := NewHub(slog.Default(), AuthConfig{Require: true, CoordPub: c.pub, Kind: meshproto.RelayKindPlatform})
	victim, victimPriv := nodeKeys(t)
	_, attackerPriv := nodeKeys(t)
	stolen := c.grant(t, victim, meshproto.RelayScopeAll, time.Now().Add(time.Hour))

	victimConn, victimRelay := net.Pipe()
	t.Cleanup(func() { _ = victimConn.Close() })
	go h.Serve(victimRelay)
	if err := handshake(t, victimConn, victim, victimPriv, stolen); err != nil {
		t.Fatalf("victim handshake: %v", err)
	}
	eventually(t, connected(h, victim, true), "victim never registered")

	// The impostor claims the victim's key, replays the victim's grant, and seals
	// with the only thing it has: its own private key.
	bad, badRelay := net.Pipe()
	t.Cleanup(func() { _ = bad.Close() })
	go h.Serve(badRelay)
	_ = handshake(t, bad, victim, attackerPriv, stolen)

	// The impostor's connection must die and the victim must still be here.
	_ = bad.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := meshproto.ReadDERPFrame(bad); err == nil {
		t.Fatal("impostor's link stayed open")
	}
	if !h.Connected(victim) {
		t.Fatal("the victim was evicted by an unauthenticated connection")
	}
}

func TestGrantChecks(t *testing.T) {
	c := newCoord(t)
	other := newCoord(t)
	nk, priv := nodeKeys(t)
	stranger, _ := nodeKeys(t)

	for _, tc := range []struct {
		name  string
		kind  meshproto.RelayKind
		grant func(*testing.T) []byte
		want  bool
	}{
		{"valid", meshproto.RelayKindPlatform, func(t *testing.T) []byte {
			return c.grant(t, nk, meshproto.RelayScopeAll, time.Now().Add(time.Hour))
		}, true},
		{"signed by someone else", meshproto.RelayKindPlatform, func(t *testing.T) []byte {
			return other.grant(t, nk, meshproto.RelayScopeAll, time.Now().Add(time.Hour))
		}, false},
		{"issued to another node", meshproto.RelayKindPlatform, func(t *testing.T) []byte {
			return c.grant(t, stranger, meshproto.RelayScopeAll, time.Now().Add(time.Hour))
		}, false},
		{"expired", meshproto.RelayKindPlatform, func(t *testing.T) []byte {
			return c.grant(t, nk, meshproto.RelayScopeAll, time.Now().Add(-time.Minute))
		}, false},
		// The quota case, both ways round: an org over its cap keeps the relays it
		// runs itself and loses the platform's.
		{"self-hosted scope on a platform relay", meshproto.RelayKindPlatform, func(t *testing.T) []byte {
			return c.grant(t, nk, meshproto.RelayScopeSelfHosted, time.Now().Add(time.Hour))
		}, false},
		{"self-hosted scope on a self-hosted relay", meshproto.RelayKindSelfHosted, func(t *testing.T) []byte {
			return c.grant(t, nk, meshproto.RelayScopeSelfHosted, time.Now().Add(time.Hour))
		}, true},
		{"no grant at all", meshproto.RelayKindPlatform, func(*testing.T) []byte { return nil }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := NewHub(slog.Default(), AuthConfig{Require: true, CoordPub: c.pub, Kind: tc.kind})
			mine, theirs := net.Pipe()
			t.Cleanup(func() { _ = mine.Close() })
			go h.Serve(theirs)
			_ = handshake(t, mine, nk, priv, tc.grant(t))

			if tc.want {
				eventually(t, connected(h, nk, true), "grant should have been accepted")
				return
			}
			_ = mine.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, _, err := meshproto.ReadDERPFrame(mine); err == nil {
				t.Fatal("link stayed open on a grant that should have been rejected")
			}
			if h.Connected(nk) {
				t.Fatal("node registered on a grant that should have been rejected")
			}
		})
	}
}

// With auth off a relay behaves exactly as it did before R0': no challenge is
// sent and a plain ClientInfo registers. This is what every relay runs until the
// fleet has upgraded, so it is not a legacy path — it is the rollout.
func TestAuthDisabledSendsNoChallenge(t *testing.T) {
	h := NewHub(slog.Default(), AuthConfig{})
	nk, _ := nodeKeys(t)

	mine, theirs := net.Pipe()
	t.Cleanup(func() { _ = mine.Close() })
	go h.Serve(theirs)
	if err := meshproto.WriteDERPFrame(mine, meshproto.DERPFrameClientInfo, nk[:]); err != nil {
		t.Fatalf("client info: %v", err)
	}
	eventually(t, connected(h, nk, true), "node was not registered with auth disabled")

	// Nothing should be waiting to be read: a challenge here would strand an old
	// node that has no idea what to do with it.
	_ = mine.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if typ, _, err := meshproto.ReadDERPFrame(mine); err == nil {
		t.Fatalf("relay sent frame type %v with auth disabled", typ)
	}
}

// A grant that has lapsed closes the link. This is what gives expiry — and
// therefore quota enforcement — any teeth at all: without it a connection
// established once would outlive the authorization behind it.
func TestSweepClosesLinkOnLapsedGrant(t *testing.T) {
	c := newCoord(t)
	now := time.Now()
	clock := func() time.Time { return now }
	h := NewHub(slog.Default(), AuthConfig{Require: true, CoordPub: c.pub, Kind: meshproto.RelayKindPlatform, Now: func() time.Time { return clock() }})
	nk, priv := nodeKeys(t)

	mine, theirs := net.Pipe()
	t.Cleanup(func() { _ = mine.Close() })
	go h.Serve(theirs)
	expiry := now.Add(30 * time.Minute)
	if err := handshake(t, mine, nk, priv, c.grant(t, nk, meshproto.RelayScopeAll, expiry)); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	eventually(t, connected(h, nk, true), "node never registered")

	// Still valid: the sweep leaves it alone.
	h.sweep()
	if !stillOpen(t, mine) {
		t.Fatal("sweep closed a link whose grant was still valid")
	}

	now = expiry.Add(time.Second)
	h.sweep()
	eventually(t, connected(h, nk, false), "sweep did not close the link after the grant lapsed")
}

// Before a grant lapses the relay asks for a fresh one IN PLACE. A healthy node
// answers with whatever its netmap refreshed and nothing is interrupted — which
// is the whole reason expiry doesn't cost every node an hourly reconnect.
func TestSweepReChallengesBeforeExpiry(t *testing.T) {
	c := newCoord(t)
	now := time.Now()
	clock := func() time.Time { return now }
	h := NewHub(slog.Default(), AuthConfig{Require: true, CoordPub: c.pub, Kind: meshproto.RelayKindPlatform, Now: func() time.Time { return clock() }})
	nk, priv := nodeKeys(t)

	mine, theirs := net.Pipe()
	t.Cleanup(func() { _ = mine.Close() })
	go h.Serve(theirs)
	expiry := now.Add(30 * time.Minute)
	if err := handshake(t, mine, nk, priv, c.grant(t, nk, meshproto.RelayScopeAll, expiry)); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	eventually(t, connected(h, nk, true), "node never registered")

	// Inside the re-auth lead. sweep writes the challenge, which blocks on a pipe
	// until we read it, so it runs alongside the node's answer.
	now = expiry.Add(-time.Minute)
	go h.sweep()

	renewed := expiry.Add(time.Hour)
	if err := answerChallenge(t, mine, nk, priv, c.grant(t, nk, meshproto.RelayScopeAll, renewed)); err != nil {
		t.Fatalf("answer re-challenge: %v", err)
	}

	// The relay must have recorded the renewed expiry — that is the fact the next
	// sweep acts on.
	eventually(t, func() bool { return grantExpiryOf(t, h, nk).Equal(renewed.Truncate(time.Second)) },
		"relay did not record the renewed grant")

	// So sweeping past the ORIGINAL expiry no longer closes anything.
	now = expiry.Add(time.Minute)
	h.sweep()
	if !stillOpen(t, mine) {
		t.Fatal("link was closed despite a renewed grant")
	}
}
