package derp

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// setReadyFallback shortens or lengthens the fallback for one test.
func setReadyFallback(t *testing.T, d time.Duration) {
	t.Helper()
	old := readyFallback
	readyFallback = d
	t.Cleanup(func() { readyFallback = old })
}

// answerPings plays a relay that never challenges: it answers every Ping.
func answerPings(conn net.Conn) {
	for {
		typ, payload, err := meshproto.ReadDERPFrame(conn)
		if err != nil {
			return
		}
		if typ == meshproto.DERPFramePing {
			_ = meshproto.WriteDERPFrame(conn, meshproto.DERPFramePong, payload)
		}
	}
}

func waitReady(c *Client, within time.Duration) bool {
	select {
	case <-c.Ready():
		return true
	case <-time.After(within):
		return false
	}
}

// A relay that does not authenticate carries packets at once; the Ping written
// at dial says so, well before the fallback.
func TestReadyAsSoonAsARelayThatNeverChallengesAnswers(t *testing.T) {
	setReadyFallback(t, time.Minute)
	self := key(1)
	addr := startRelay(t, self, answerPings)
	c, err := Dial(context.Background(), addr, self, Auth{}, nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if !waitReady(c, 3*time.Second) {
		t.Fatal("a relay that answered the dial's Ping did not make the link ready")
	}
}

// A relay that authenticates discards the dial's Ping (it comes before the
// proof); the Ping written behind the proof is what it answers once it admits
// the link — well before the fallback.
func TestReadyOnceTheRelayAdmitsTheLink(t *testing.T) {
	setReadyFallback(t, time.Minute)
	self, priv := nodeKeys(t)
	addr := startRelay(t, self, func(conn net.Conn) {
		ch, ephPriv, err := meshproto.NewDERPAuthChallenge()
		if err != nil {
			return
		}
		_ = meshproto.WriteDERPFrame(conn, meshproto.DERPFrameAuthChallenge, ch.Encode())
		for {
			typ, p, err := meshproto.ReadDERPFrame(conn)
			if err != nil {
				return
			}
			if typ != meshproto.DERPFrameAuthProof {
				continue // discarded before the proof, the dial's Ping included
			}
			if _, err := meshproto.OpenDERPAuthProof(ch, ephPriv, self, p); err != nil {
				return
			}
			break
		}
		answerPings(conn)
	})
	c, err := Dial(context.Background(), addr, self, Auth{Priv: priv, Grant: func() []byte { return []byte("g") }}, nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if !waitReady(c, 3*time.Second) {
		t.Fatal("the relay admitted the link, but it never became ready")
	}
}

// A relay that challenges and never admits the link: not ready, however many
// Pings the link writes (the relay discards them, as pkg/relay does before a
// proof it accepts).
func TestNotReadyUntilTheRelayAdmitsTheLink(t *testing.T) {
	setReadyFallback(t, time.Minute)
	self, priv := nodeKeys(t)
	addr := startRelay(t, self, func(conn net.Conn) {
		ch, _, err := meshproto.NewDERPAuthChallenge()
		if err != nil {
			return
		}
		_ = meshproto.WriteDERPFrame(conn, meshproto.DERPFrameAuthChallenge, ch.Encode())
		for {
			if _, _, err := meshproto.ReadDERPFrame(conn); err != nil {
				return // proof and Pings alike, discarded
			}
		}
	})
	c, err := Dial(context.Background(), addr, self, Auth{Priv: priv, Grant: func() []byte { return []byte("g") }}, nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if waitReady(c, 300*time.Millisecond) {
		t.Fatal("the link was ready before the relay admitted it")
	}
}

// A relay that answers nothing at all is taken as ready after the fallback —
// how every link was treated before — so a relay without Pongs is not cut off.
func TestASilentRelayIsTakenAsReadyAfterTheFallback(t *testing.T) {
	setReadyFallback(t, 100*time.Millisecond)
	self := key(1)
	addr := startRelay(t, self, func(conn net.Conn) {
		for {
			if _, _, err := meshproto.ReadDERPFrame(conn); err != nil {
				return
			}
		}
	})
	start := time.Now()
	c, err := Dial(context.Background(), addr, self, Auth{}, nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if !waitReady(c, 3*time.Second) {
		t.Fatal("a silent relay's link never became ready")
	}
	if waited := time.Since(start); waited < 100*time.Millisecond {
		t.Fatalf("ready after %v, before the fallback", waited)
	}
}
