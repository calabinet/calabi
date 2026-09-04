package mesh

import (
	"fmt"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

func loopback(port uint16) netip.AddrPort {
	return netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", port))
}

// A ping sent to a peer's socket is auto-answered with a pong the sender's read
// loop delivers to its handler — the full DISCO round-trip over real sockets.
func TestMagicSockDiscoPingPong(t *testing.T) {
	aKey, _ := GenerateDiscoKey()
	bKey, _ := GenerateDiscoKey()
	a, err := newMagicSock(aKey, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := newMagicSock(bKey, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	type pong struct {
		peer meshproto.DiscoKey
		tx   discoTxID
	}
	got := make(chan pong, 1)
	a.setPongHandler(func(peer meshproto.DiscoKey, tx discoTxID, _ netip.AddrPort) {
		got <- pong{peer, tx}
	})

	tx, err := a.SendPing(bKey.Public(), loopback(b.LocalPort()))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-got:
		if p.peer != bKey.Public() {
			t.Fatalf("pong peer = %s, want b", p.peer)
		}
		if p.tx != tx {
			t.Fatalf("pong tx = %x, want %x", p.tx, tx)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no pong received")
	}
}

// The prober pings a peer and, once the peer auto-pongs, exposes the working
// endpoint as the peer's best direct path.
func TestDiscoProberValidatesPath(t *testing.T) {
	aKey, _ := GenerateDiscoKey()
	bKey, _ := GenerateDiscoKey()
	a, err := newMagicSock(aKey, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := newMagicSock(bKey, slog.Default()) // auto-pongs from its read loop
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	prober := newDiscoProber(a, slog.Default())
	bAddr := loopback(b.LocalPort())
	prober.Probe([]Peer{{DiscoKey: bKey.Public(), Endpoints: []netip.AddrPort{bAddr}}})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ep, ok := prober.bestPath(bKey.Public()); ok {
			if ep != bAddr {
				t.Fatalf("bestPath = %s, want %s", ep, bAddr)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("direct path never validated")
}

// A peer we never probed has no path, and an unsolicited pong (a tx we didn't
// send) can't manufacture one.
func TestDiscoProberRejectsUnsolicited(t *testing.T) {
	aKey, _ := GenerateDiscoKey()
	a, err := newMagicSock(aKey, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	prober := newDiscoProber(a, slog.Default())

	other, _ := GenerateDiscoKey()
	if _, ok := prober.bestPath(other.Public()); ok {
		t.Fatal("an unprobed peer must have no path")
	}
	prober.onPong(other.Public(), discoTxID{1, 2, 3}, netip.MustParseAddrPort("203.0.113.9:5"))
	if _, ok := prober.bestPath(other.Public()); ok {
		t.Fatal("an unsolicited pong must not validate a path")
	}
}

// A symmetric-NAT peer's reachable port never appears in its netmap, so probing
// only its advertised (unreachable) endpoint never validates. Once the prober
// LEARNS the port from the peer's own DISCO packet (learnCandidate — the
// noteDiscoSource path), it probes that too and validates the direct return path
// the cone side would otherwise miss. This is the symmetric↔cone fix.
func TestDiscoProberProbesLearnedCandidate(t *testing.T) {
	aKey, _ := GenerateDiscoKey()
	bKey, _ := GenerateDiscoKey()
	a, err := newMagicSock(aKey, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := newMagicSock(bKey, slog.Default()) // auto-pongs from its read loop
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	prober := newDiscoProber(a, slog.Default())
	bReal := loopback(b.LocalPort())                    // the port that actually reaches b
	dead := netip.MustParseAddrPort("203.0.113.7:9")    // b's only "advertised" endpoint — unreachable

	// The peer advertises only the unreachable endpoint; the real port is learned
	// from its incoming DISCO, exactly as meshBind.noteDiscoSource feeds it.
	prober.learnCandidate(bKey.Public(), bReal)
	prober.Probe([]Peer{{DiscoKey: bKey.Public(), Endpoints: []netip.AddrPort{dead}}})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ep, ok := prober.bestPath(bKey.Public()); ok {
			if ep != bReal {
				t.Fatalf("bestPath = %s, want learned %s", ep, bReal)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("learned candidate never validated a direct path")
}
