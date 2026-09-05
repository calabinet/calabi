package mesh

// prober_path_test.go — which endpoint a peer's direct path settles on when MORE
// THAN ONE of them works.
//
// Two things have to hold at once, and they pull in opposite directions.
//
// DON'T CHURN. onPong used to take the last pong unconditionally. Two reachable
// endpoints — two container networks between the same pair of hosts, a machine
// on two LANs, v4 and v6 — then overwrote each other once per probe round: the
// transport choice churned, and the "direct path found" line (which only prints
// on a change) repeated every 5s forever. pathSticky keeps the path that is
// already carrying traffic, without stranding a peer on an endpoint that went
// quiet.
//
// DO MOVE WHEN IT MATTERS. "Direct" means "not through the relay", not "over the
// LAN". Two machines on one LAN advertise both their private address and the
// public one their NAT maps them to, and both answer — the public one because
// the router hairpins the packet back in. Both are direct; measured on a home
// LAN, one does ~500 MB/s and the other ~0.3 MB/s. Keeping whichever answered
// first was how a peer ended up pinned to the hairpin for good, so a sibling
// that is quicker BY A WIDE MARGIN (pathFasterRatio + pathFasterFloor) takes
// over — the margin being what keeps this from re-introducing the churn above.

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
// answer. Returns the tx id to answer with. The answer measures as instant.
func seedProbe(p *discoProber, peer meshproto.DiscoKey, ep netip.AddrPort, tx byte) discoTxID {
	return seedProbeRTT(p, peer, ep, tx, 0)
}

// seedProbeRTT is seedProbe with a chosen round-trip: it backdates the ping so
// the pong that answers it measures as rtt. Endpoints that differ by orders of
// magnitude are the whole point here and a loopback pair can't produce them.
func seedProbeRTT(p *discoProber, peer meshproto.DiscoKey, ep netip.AddrPort, tx byte, rtt time.Duration) discoTxID {
	id := discoTxID{tx}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pending[id] = pendingProbe{peer: peer, ep: ep, sent: time.Now().Add(-rtt)}
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

// The reported case (2026-09-05): a Windows box and a Linux box on one LAN, the
// Linux one publishing a subnet route to the LAN's NAS. The mesh settled on the
// peer's PUBLIC endpoint, so every NAS request left for the ISP and hairpinned
// back — 0.3 MB/s, and `stat` on an SMB share took 27ms.
//
// Both endpoints answer, so the prober has to land on the quick one whichever
// pong arrives first. Delete the `case quicker(...)` arm from onPong and the
// "public answers first" subtest fails (verified).
func TestDiscoProberPrefersTheQuickerOfTwoWorkingEndpoints(t *testing.T) {
	lan := netip.MustParseAddrPort("192.168.1.23:41641")
	public := netip.MustParseAddrPort("171.222.188.176:22237")

	for _, tc := range []struct {
		name      string
		first     netip.AddrPort
		firstRTT  time.Duration
		second    netip.AddrPort
		secondRTT time.Duration
	}{
		{"public answers first", public, 8 * time.Millisecond, lan, 400 * time.Microsecond},
		{"lan answers first", lan, 400 * time.Microsecond, public, 8 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, _ := GenerateDiscoKey()
			peer := key.Public()
			p, _ := newLoggedProber(t)

			p.onPong(peer, seedProbeRTT(p, peer, tc.first, 1, tc.firstRTT), tc.first)
			p.onPong(peer, seedProbeRTT(p, peer, tc.second, 2, tc.secondRTT), tc.second)

			got, ok := p.bestPath(peer)
			if !ok {
				t.Fatal("no direct path, though two endpoints answered")
			}
			if got != lan {
				t.Fatalf("path = %s, want the LAN endpoint %s — the hairpinned public path is "+
					"three orders of magnitude slower", got, lan)
			}
		})
	}
}

// The margin, from the other side: a sibling that answers a little sooner is not
// a reason to move. Two endpoints on one LAN differ by scheduling jitter, and
// every move costs a fresh handshake. Without pathFasterFloor this flaps.
func TestDiscoProberKeepsPathWhenSiblingIsBarelyQuicker(t *testing.T) {
	key, _ := GenerateDiscoKey()
	peer := key.Public()
	incumbent := netip.MustParseAddrPort("192.168.1.23:41641")
	sibling := netip.MustParseAddrPort("10.8.0.4:41641")

	p, log := newLoggedProber(t)
	p.onPong(peer, seedProbeRTT(p, peer, incumbent, 1, 5*time.Millisecond), incumbent)
	p.onPong(peer, seedProbeRTT(p, peer, sibling, 2, 4*time.Millisecond), sibling)

	got, _ := p.bestPath(peer)
	if got != incumbent {
		t.Fatalf("path = %s, want it to stay on %s — 4ms against 5ms is churn, not an improvement", got, incumbent)
	}
	if n := strings.Count(log.String(), "mesh direct path changed"); n != 0 {
		t.Fatalf("logged %d path changes, want 0:\n%s", n, log.String())
	}
}

// Speed never outranks liveness: once the path in use goes quiet, an endpoint
// that still answers takes over however slow it is, because the alternative is
// the relay.
func TestDiscoProberTakesASlowerPathWhenTheQuickOneGoesQuiet(t *testing.T) {
	key, _ := GenerateDiscoKey()
	peer := key.Public()
	quick := netip.MustParseAddrPort("192.168.1.23:41641")
	slow := netip.MustParseAddrPort("171.222.188.176:22237")

	p, _ := newLoggedProber(t)
	p.onPong(peer, seedProbeRTT(p, peer, quick, 1, 400*time.Microsecond), quick)
	agePath(p, peer, pathSticky+time.Second)

	p.onPong(peer, seedProbeRTT(p, peer, slow, 2, 8*time.Millisecond), slow)

	got, ok := p.bestPath(peer)
	if !ok {
		t.Fatal("dropped to the relay instead of taking the endpoint that still answers")
	}
	if got != slow {
		t.Fatalf("path = %s, want %s — a slow path beats no path", got, slow)
	}
}
