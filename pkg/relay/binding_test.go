package relay

import (
	"crypto/rand"
	"log/slog"
	"net"
	"testing"
	"time"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

// A TLS link answers with a proof bound to the certificate this relay
// presented on it; a plaintext link with the legacy one. These tests
// drive the hub the way the edge does after terminating TLS: ServeBound with
// the binding of the certificate it served. The TLS itself is the edge's
// (apps/calabi-edge/cmd/calabi-edge/relayrole.go) — this package never sees
// it, and its tests stay on stdlib pipes like the rest.

// someBinding is the binding of a certificate nobody in the test presents.
func someBinding(t *testing.T) meshproto.DERPBinding {
	t.Helper()
	var b meshproto.DERPBinding
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return b
}

// sealer is how a test node answers a challenge: legacy or bound, and to what.
type sealer func(ch meshproto.DERPAuthChallenge, claim meshproto.NodeKey, priv [meshproto.KeyLen]byte, grant []byte) ([]byte, error)

func legacyProof(ch meshproto.DERPAuthChallenge, claim meshproto.NodeKey, priv [meshproto.KeyLen]byte, grant []byte) ([]byte, error) {
	return meshproto.SealDERPAuthProof(ch, claim, priv, grant)
}

func boundProof(b meshproto.DERPBinding) sealer {
	return func(ch meshproto.DERPAuthChallenge, claim meshproto.NodeKey, priv [meshproto.KeyLen]byte, grant []byte) ([]byte, error) {
		return meshproto.SealBoundDERPAuthProof(ch, claim, priv, grant, b)
	}
}

// answerWith reads the relay's challenge off conn and answers it with seal.
func answerWith(t *testing.T, conn net.Conn, claim meshproto.NodeKey, priv [meshproto.KeyLen]byte, grant []byte, seal sealer) error {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	typ, payload, err := meshproto.ReadDERPFrame(conn)
	if err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Time{})
	if typ != meshproto.DERPFrameAuthChallenge {
		t.Fatalf("expected a challenge, got frame type %v", typ)
	}
	ch, err := meshproto.ParseDERPAuthChallenge(payload)
	if err != nil {
		return err
	}
	proof, err := seal(ch, claim, priv, grant)
	if err != nil {
		return err
	}
	return meshproto.WriteDERPFrame(conn, meshproto.DERPFrameAuthProof, proof)
}

// admitted reports whether the relay let the link in: it closes a link that
// failed to authenticate, and registers one that did.
func admitted(t *testing.T, h *Hub, k meshproto.NodeKey, conn net.Conn) bool {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if h.Connected(k) {
			return true
		}
		_ = conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		if _, _, err := meshproto.ReadDERPFrame(conn); err != nil {
			if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
				return false // the relay hung up
			}
		}
	}
	return h.Connected(k)
}

func TestLinkTakesOnlyTheProofItsTransportCalls(t *testing.T) {
	c := newCoord(t)
	served := someBinding(t)
	for _, tc := range []struct {
		name  string
		bound bool // the link arrived over TLS, and the relay served `served`
		seal  sealer
		want  bool
	}{
		{"TLS link, proof bound to the certificate it was served", true, boundProof(served), true},
		// in miniature: the answer a node gave another relay's link.
		{"TLS link, proof bound to another certificate", true, boundProof(someBinding(t)), false},
		// A proof harvested on some plaintext link must not open a TLS one.
		{"TLS link, legacy proof", true, legacyProof, false},
		{"plaintext link, legacy proof", false, legacyProof, true},
		// And the other way: the bound format is not a legacy proof with extra
		// bytes, whatever it is bound to.
		{"plaintext link, bound proof", false, boundProof(served), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := NewHub(slog.Default(), AuthConfig{Require: true, CoordPub: c.pub, Kind: meshproto.RelayKindPlatform})
			nk, priv := nodeKeys(t)
			mine, theirs := net.Pipe()
			t.Cleanup(func() { _ = mine.Close() })
			if tc.bound {
				go h.ServeBound(theirs, served)
			} else {
				go h.Serve(theirs)
			}
			if err := meshproto.WriteDERPFrame(mine, meshproto.DERPFrameClientInfo, nk[:]); err != nil {
				t.Fatalf("client info: %v", err)
			}
			grant := c.grant(t, nk, meshproto.RelayScopeAll, time.Now().Add(time.Hour))
			if err := answerWith(t, mine, nk, priv, grant, tc.seal); err != nil {
				t.Fatalf("answer: %v", err)
			}
			if got := admitted(t, h, nk, mine); got != tc.want {
				t.Fatalf("admitted = %v, want %v", got, tc.want)
			}
		})
	}
}

// A re-challenge on a live TLS link is held to the same rule as the first one:
// the renewed grant arrives in a bound proof, or the link is closed. Without it,
// a link that authenticated properly once could be taken over at its first
// re-authentication.
func TestReauthOnATLSLinkStaysBound(t *testing.T) {
	c := newCoord(t)
	served := someBinding(t)
	for _, tc := range []struct {
		name string
		seal sealer
		keep bool
	}{
		{"bound answer", boundProof(served), true},
		{"legacy answer", legacyProof, false},
		{"answer bound to another certificate", boundProof(someBinding(t)), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now()
			h := NewHub(slog.Default(), AuthConfig{Require: true, CoordPub: c.pub, Kind: meshproto.RelayKindPlatform,
				Now: func() time.Time { return now }})
			nk, priv := nodeKeys(t)
			mine, theirs := net.Pipe()
			t.Cleanup(func() { _ = mine.Close() })
			go h.ServeBound(theirs, served)
			if err := meshproto.WriteDERPFrame(mine, meshproto.DERPFrameClientInfo, nk[:]); err != nil {
				t.Fatalf("client info: %v", err)
			}
			expiry := now.Add(30 * time.Minute)
			if err := answerWith(t, mine, nk, priv, c.grant(t, nk, meshproto.RelayScopeAll, expiry), boundProof(served)); err != nil {
				t.Fatalf("answer: %v", err)
			}
			eventually(t, connected(h, nk, true), "node never registered")

			now = expiry.Add(-time.Minute) // inside the re-auth lead
			go h.sweep()
			renewed := expiry.Add(time.Hour)
			if err := answerWith(t, mine, nk, priv, c.grant(t, nk, meshproto.RelayScopeAll, renewed), tc.seal); err != nil {
				t.Fatalf("answer re-challenge: %v", err)
			}
			if tc.keep {
				eventually(t, func() bool { return grantExpiryOf(t, h, nk).Equal(renewed.Truncate(time.Second)) },
					"relay did not take the renewed grant from a bound answer")
				return
			}
			eventually(t, connected(h, nk, false), "relay kept a TLS link whose re-authentication was not bound to it")
		})
	}
}
