package mesh

// prober_path_test.go — which endpoint a peer's direct path settles on when MORE
// THAN ONE of them works.
//
// onPong used to take the last pong unconditionally. Two reachable endpoints —
// two container networks between the same pair of hosts, a machine on two LANs,
// v4 and v6 — then overwrote each other once per probe round: the transport
// choice churned, and the "direct path found" line (which only prints on a
// change) repeated every 5s forever. pathSticky keeps the path that is already
// carrying traffic, without stranding a peer on an endpoint that went quiet.

import (
	"bytes"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// seedProbe registers a ping as if Probe had just sent it, so onPong accepts the
// answer. Returns the tx id to answer with.
func seedProbe(p *discoProber, peer meshproto.DiscoKey, ep netip.AddrPort, tx byte) discoTxID {
	id := discoTxID{tx}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pending[id] = pendingProbe{peer: peer, ep: ep, sent: time.Now()}
	return id
}

// agePath backdates the confirmation of the peer's current path, standing in for
// "this endpoint stopped answering d ago".
func agePath(p *discoProber, peer meshproto.DiscoKey, d time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	cur := p.paths[peer]
	cur.confirmed = time.Now().Add(-d)
	p.paths[peer] = cur
}

func newLoggedProber(t *testing.T) (*discoProber, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	return &discoProber{
		logger:  slog.New(slog.NewTextHandler(&buf, nil)),
		pending: make(map[discoTxID]pendingProbe),
		paths:   make(map[meshproto.DiscoKey]peerPath),
		learned: make(map[meshproto.DiscoKey]map[netip.AddrPort]time.Time),
	}, &buf
}

// The reported symptom: a peer answering on two endpoints logged a "path found"
// on every probe round, because the path itself flipped on every round.
func TestDiscoProberKeepsOnePathWhenTwoEndpointsAnswer(t *testing.T) {
	key, _ := GenerateDiscoKey()
	peer := key.Public()
	epA := netip.MustParseAddrPort("10.89.2.2:38695")
	epB := netip.MustParseAddrPort("10.89.3.1:38695")

	p, log := newLoggedProber(t)

	// Five probe rounds, both endpoints answering each time (B last — the loser
	// under "last pong wins").
	for i := range 5 {
		p.onPong(peer, seedProbe(p, peer, epA, byte(2*i)), epA)
		p.onPong(peer, seedProbe(p, peer, epB, byte(2*i+1)), epB)
	}

	got, ok := p.bestPath(peer)
	if !ok {
		t.Fatal("no path at all")
	}
	if got != epA {
		t.Fatalf("path = %s, want the first one validated (%s) — it flipped", got, epA)
	}
	if n := strings.Count(log.String(), "mesh direct path"); n != 1 {
		t.Fatalf("logged %d path lines over 5 rounds, want exactly 1:\n%s", n, log.String())
	}
}

// Staying put must not mean staying stale: if the endpoint in use goes quiet, a
// sibling that still answers takes over — and does so BEFORE bestPath gives up
// and drops the peer to the relay.
func TestDiscoProberMovesOffAQuietEndpoint(t *testing.T) {
	if pathSticky >= pathTTL {
		t.Fatalf("pathSticky (%s) must be below pathTTL (%s), or a peer falls back to the relay "+
			"instead of moving to a working sibling endpoint", pathSticky, pathTTL)
	}

	key, _ := GenerateDiscoKey()
	peer := key.Public()
	epA := netip.MustParseAddrPort("10.89.2.2:38695")
	epB := netip.MustParseAddrPort("10.89.3.1:38695")

	p, log := newLoggedProber(t)
	p.onPong(peer, seedProbe(p, peer, epA, 1), epA)

	// A answers once more within the sticky window: B must not steal the path.
	p.onPong(peer, seedProbe(p, peer, epB, 2), epB)
	if got, _ := p.bestPath(peer); got != epA {
		t.Fatalf("path = %s, want %s while A is still fresh", got, epA)
	}

	// A goes quiet past the sticky window; B is still answering.
	agePath(p, peer, pathSticky+time.Second)
	p.onPong(peer, seedProbe(p, peer, epB, 3), epB)

	got, ok := p.bestPath(peer)
	if !ok {
		t.Fatal("peer lost its path entirely instead of moving to the working endpoint")
	}
	if got != epB {
		t.Fatalf("path = %s, want %s after A went quiet", got, epB)
	}
	if !strings.Contains(log.String(), "mesh direct path changed") {
		t.Fatalf("a real path change must be logged:\n%s", log.String())
	}
}

// A pong for the endpoint already in use refreshes it — otherwise a path that
// keeps working would still age out of pathTTL and drop to the relay.
func TestDiscoProberRefreshesTheCurrentPath(t *testing.T) {
	key, _ := GenerateDiscoKey()
	peer := key.Public()
	ep := netip.MustParseAddrPort("10.89.2.2:38695")

	p, _ := newLoggedProber(t)
	p.onPong(peer, seedProbe(p, peer, ep, 1), ep)
	agePath(p, peer, pathTTL-time.Second) // nearly expired
	p.onPong(peer, seedProbe(p, peer, ep, 2), ep)

	p.mu.Lock()
	age := time.Since(p.paths[peer].confirmed)
	p.mu.Unlock()
	if age > time.Second {
		t.Fatalf("confirmed is %s old; the pong for the current path did not refresh it", age)
	}
}

// Stickiness must not slow down the write-failure path: the bind retires a dead
// path explicitly, and the next pong — from any endpoint — takes over at once.
func TestDiscoProberInvalidateBeatsStickiness(t *testing.T) {
	key, _ := GenerateDiscoKey()
	peer := key.Public()
	epA := netip.MustParseAddrPort("10.89.2.2:38695")
	epB := netip.MustParseAddrPort("10.89.3.1:38695")

	p, _ := newLoggedProber(t)
	p.onPong(peer, seedProbe(p, peer, epA, 1), epA)
	p.invalidatePath(peer)
	p.onPong(peer, seedProbe(p, peer, epB, 2), epB)

	if got, ok := p.bestPath(peer); !ok || got != epB {
		t.Fatalf("path = %s (ok=%v), want %s immediately after invalidatePath", got, ok, epB)
	}
}
