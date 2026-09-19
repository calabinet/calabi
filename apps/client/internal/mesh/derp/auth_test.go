package derp

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

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

// The node proves it holds the key it announced, and does so with the grant it
// holds AT THAT MOMENT. The second challenge is the point: a relay may
// re-challenge a link hours after it was dialed, by which time the netmap has
// handed the node a fresher grant — presenting the stale one would get the link
// closed exactly when the node was doing everything right.
func TestClientAnswersChallengeWithTheCurrentGrant(t *testing.T) {
	self, priv := nodeKeys(t)
	var grant atomic.Value
	grant.Store([]byte("grant-v1"))

	type answer struct {
		grant []byte
		err   error
	}
	answers := make(chan answer, 2)
	// The relay holds the re-challenge until the test has refreshed the grant.
	// Without the gate it sends the second challenge the instant it has read the
	// first proof, and a client that answers before grant.Store runs presents
	// grant-v1 quite correctly — the test would be racing itself, not the client.
	refreshed := make(chan struct{})

	addr := startRelay(t, self, func(conn net.Conn) {
		for i := 0; i < 2; i++ {
			if i == 1 {
				select {
				case <-refreshed:
				case <-t.Context().Done():
					return
				}
			}
			ch, ephPriv, err := meshproto.NewDERPAuthChallenge()
			if err != nil {
				answers <- answer{err: err}
				return
			}
			if err := meshproto.WriteDERPFrame(conn, meshproto.DERPFrameAuthChallenge, ch.Encode()); err != nil {
				answers <- answer{err: err}
				return
			}
			typ, payload, err := readSkippingPings(conn)
			if err != nil {
				answers <- answer{err: err}
				return
			}
			if typ != meshproto.DERPFrameAuthProof {
				answers <- answer{err: errFrameType(typ)}
				return
			}
			g, err := meshproto.OpenDERPAuthProof(ch, ephPriv, self, payload)
			answers <- answer{grant: g, err: err}
		}
	})

	c, err := Dial(context.Background(), addr, self, Auth{Priv: priv, Grant: func() []byte {
		return grant.Load().([]byte)
	}}, nil, slog.Default())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	first := recvAnswer(t, answers)
	if first.err != nil {
		t.Fatalf("relay could not open the first proof: %v", first.err)
	}
	if string(first.grant) != "grant-v1" {
		t.Fatalf("first proof carried %q, want %q", first.grant, "grant-v1")
	}

	// The netmap refreshes the grant; the next challenge must pick it up.
	grant.Store([]byte("grant-v2"))
	close(refreshed)
	second := recvAnswer(t, answers)
	if second.err != nil {
		t.Fatalf("relay could not open the second proof: %v", second.err)
	}
	if string(second.grant) != "grant-v2" {
		t.Fatalf("re-challenge carried the stale grant %q, want %q", second.grant, "grant-v2")
	}
}

// A link with no key configured says nothing rather than sending a proof that
// cannot verify. Both end with the relay closing the link, but silence is what
// leaves a usable trail in the logs.
func TestClientWithoutKeyStaysSilent(t *testing.T) {
	self, _ := nodeKeys(t)
	got := make(chan meshproto.DERPFrameType, 1)

	addr := startRelay(t, self, func(conn net.Conn) {
		ch, _, err := meshproto.NewDERPAuthChallenge()
		if err != nil {
			return
		}
		if err := meshproto.WriteDERPFrame(conn, meshproto.DERPFrameAuthChallenge, ch.Encode()); err != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		typ, _, err := readSkippingPings(conn)
		if err == nil {
			got <- typ
		}
		close(got)
	})

	c, err := Dial(context.Background(), addr, self, Auth{}, nil, slog.Default())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	if typ, ok := <-got; ok {
		t.Fatalf("client answered a challenge with no key configured (frame type %v)", typ)
	}
}

// A link the relay challenged and then hung up on keeps the facts the relay pool
// needs to call that a refusal: that it was challenged, which grant it answered
// with, and how long it lasted — frozen at the moment it ended, not still growing.
func TestClientRemembersTheChallengeItWasClosedOn(t *testing.T) {
	self, priv := nodeKeys(t)
	addr := startRelay(t, self, func(conn net.Conn) {
		defer conn.Close()
		ch, _, err := meshproto.NewDERPAuthChallenge()
		if err != nil {
			return
		}
		if err := meshproto.WriteDERPFrame(conn, meshproto.DERPFrameAuthChallenge, ch.Encode()); err != nil {
			return
		}
		_, _, _ = readSkippingPings(conn) // the proof; then turned away, as a relay does with an expired grant
	})

	c, err := Dial(context.Background(), addr, self, Auth{Priv: priv, Grant: func() []byte { return []byte("stale") }}, nil, slog.Default())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	select {
	case <-c.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("the relay's hang-up never reached the client")
	}

	grant, challenged := c.Challenged()
	if !challenged || string(grant) != "stale" {
		t.Fatalf("Challenged() = %q, %v; want the grant it answered with, true", grant, challenged)
	}
	lived := c.Lifetime()
	time.Sleep(20 * time.Millisecond)
	if again := c.Lifetime(); again != lived {
		t.Fatalf("Lifetime kept counting after the link ended: %v, then %v", lived, again)
	}
}

// A relay that never asks is not remembered as having asked.
func TestClientNotChallengedByAnOpenRelay(t *testing.T) {
	self, priv := nodeKeys(t)
	addr := startRelay(t, self, func(conn net.Conn) { _ = conn.Close() })

	c, err := Dial(context.Background(), addr, self, Auth{Priv: priv}, nil, slog.Default())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	select {
	case <-c.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("the relay's hang-up never reached the client")
	}
	if _, challenged := c.Challenged(); challenged {
		t.Fatal("a link that was never challenged reports a challenge")
	}
}

type frameTypeError meshproto.DERPFrameType

func (e frameTypeError) Error() string { return "unexpected frame type" }

func errFrameType(t meshproto.DERPFrameType) error { return frameTypeError(t) }

func recvAnswer[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for the relay to process a proof")
	}
	var zero T
	return zero
}
