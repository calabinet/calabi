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

	addr := startRelay(t, self, func(conn net.Conn) {
		for i := 0; i < 2; i++ {
			ch, ephPriv, err := meshproto.NewDERPAuthChallenge()
			if err != nil {
				answers <- answer{err: err}
				return
			}
			if err := meshproto.WriteDERPFrame(conn, meshproto.DERPFrameAuthChallenge, ch.Encode()); err != nil {
				answers <- answer{err: err}
				return
			}
			typ, payload, err := meshproto.ReadDERPFrame(conn)
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
		typ, _, err := meshproto.ReadDERPFrame(conn)
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
