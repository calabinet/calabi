package mesh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// grantRelay authenticates links the way a real relay does (R0′): it challenges
// each one, opens the proof, and lets the link in only if it carries the grant
// the relay currently accepts. Anything else it turns away by hanging up — which
// is what pkg/relay's hub does with an expired grant, and all a device ever gets
// to see of it. Admitted links get their keepalives answered.
type grantRelay struct {
	t    *testing.T
	addr string
	self meshproto.NodeKey

	mu sync.Mutex
	// accept is the grant it lets in; nil turns every link away.
	accept []byte
	// hangUp makes it close each link straight after ClientInfo, without a
	// challenge: a relay on its way down, or a TCP proxy whose relay is.
	hangUp bool
	dials  []time.Time // when each link arrived
	shown  [][]byte    // the grant each challenged link answered with
}

func startGrantRelay(t *testing.T, self meshproto.NodeKey) *grantRelay {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &grantRelay{t: t, addr: ln.Addr().String(), self: self}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(conn)
		}
	}()
	return s
}

func (s *grantRelay) serve(conn net.Conn) {
	defer conn.Close()
	s.mu.Lock()
	s.dials = append(s.dials, time.Now())
	hangUp := s.hangUp
	s.mu.Unlock()
	if typ, _, err := meshproto.ReadDERPFrame(conn); err != nil || typ != meshproto.DERPFrameClientInfo || hangUp {
		return
	}
	ch, ephPriv, err := meshproto.NewDERPAuthChallenge()
	if err != nil {
		return
	}
	if err := meshproto.WriteDERPFrame(conn, meshproto.DERPFrameAuthChallenge, ch.Encode()); err != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var payload []byte
	for {
		typ, p, err := meshproto.ReadDERPFrame(conn)
		if err != nil {
			return
		}
		if typ == meshproto.DERPFrameAuthProof {
			payload = p
			break
		}
	}
	grant, err := meshproto.OpenDERPAuthProof(ch, ephPriv, s.self, payload)
	s.mu.Lock()
	s.shown = append(s.shown, grant)
	admit := err == nil && s.accept != nil && bytes.Equal(grant, s.accept)
	s.mu.Unlock()
	if !admit {
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	for {
		typ, p, err := meshproto.ReadDERPFrame(conn)
		if err != nil {
			return
		}
		if typ == meshproto.DERPFramePing {
			_ = meshproto.WriteDERPFrame(conn, meshproto.DERPFramePong, p)
		}
	}
}

func (s *grantRelay) setAccept(g []byte) {
	s.mu.Lock()
	s.accept = g
	s.mu.Unlock()
}

func (s *grantRelay) dialTimes() []time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Time(nil), s.dials...)
}

func (s *grantRelay) dialCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.dials)
}

func (s *grantRelay) lastShown() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.shown) == 0 {
		return nil
	}
	return s.shown[len(s.shown)-1]
}

// waitDial waits up to within for a link beyond the first n, and reports whether
// one came.
func (s *grantRelay) waitDial(n int, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if s.dialCount() > n {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return s.dialCount() > n
}

// refusalTestEvery is the keepalive interval these tests run the pool at. A
// refusal on loopback takes well under a millisecond, so it sits far inside the
// one-interval window, and the holds (2, 4, 8… intervals) are far enough apart
// that "dialed at once" and "dialed after the hold" can't be confused.
const refusalTestEvery = 50 * time.Millisecond

func newRefusalTestPool(t *testing.T, priv PrivateKey) *relayPool {
	t.Helper()
	p := newRelayPoolTimed(priv.Public(), [meshproto.KeyLen]byte(priv), nil, slog.Default(), refusalTestEvery, time.Minute)
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// waitHeld waits until the pool has been refused `times` times in a row by the
// relay at addr and is sitting out the hold: no link, no dial in flight. Tests
// that go on to prove something happens "at once" must start from here — a dial
// already under way would present whatever grant is current by the time the
// relay challenges it, and pass for the wrong reason.
func waitHeld(t *testing.T, p *relayPool, addr string, times int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		p.mu.Lock()
		r := p.refusals[addr]
		held := r != nil && r.times >= times && p.clients[addr] == nil && !p.dialing[addr] && p.heldLocked(addr)
		got := 0
		if r != nil {
			got = r.times
		}
		p.mu.Unlock()
		if held {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("pool never sat out a hold after %d refusals (got %d)", times, got)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func refusalCount(p *relayPool) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.refusals)
}

// signedGrant is a real grant, so the pool can read its terms. Different expiries
// give different bytes with the same terms — what the coordinator does when it
// signs a fresh grant into every netmap.
func signedGrant(t *testing.T, key ed25519.PrivateKey, node meshproto.NodeKey, scope meshproto.RelayScope, expiresIn time.Duration) []byte {
	t.Helper()
	g, err := meshproto.SignRelayGrant(key, meshproto.RelayGrant{Node: node, Meshnet: 1, Scope: scope, Expiry: time.Now().Add(expiresIn)})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// The regression from the self-hosted server acceptance: a device whose
// grant has lapsed was turned away by its home relay and re-dialed it on every
// sweep, forever — one connection and one WARN on the edge every 15 seconds.
// The re-dials must now spread out (one interval, then two, four, …), and must
// not stop.
func TestRelayPoolBacksOffARelayThatTurnsItAway(t *testing.T) {
	priv := testKey(7)
	relay := startGrantRelay(t, priv.Public()) // accepts nothing
	p := newRefusalTestPool(t, priv)
	p.SetGrant([]byte("a grant that has run out"))
	if err := p.DialHome(context.Background(), relay.addr); err != nil {
		t.Fatalf("dial home: %v", err)
	}

	time.Sleep(30 * refusalTestEvery)

	// With a hold that doubles from one interval, the dials land at about 0, 2,
	// 5, 10 and 19 intervals. Re-dialing every sweep would be about 30.
	dials := relay.dialTimes()
	if len(dials) > 8 {
		t.Fatalf("relay saw %d links in %d sweeps; the pool is still re-dialing a relay that refuses it every sweep",
			len(dials), 30)
	}
	if len(dials) < 3 {
		t.Fatalf("relay saw only %d links in %d sweeps; the pool must keep asking, just less often", len(dials), 30)
	}
	first, last := dials[1].Sub(dials[0]), dials[len(dials)-1].Sub(dials[len(dials)-2])
	if last < 3*first {
		t.Fatalf("gaps between re-dials did not grow: first %v, last %v (all: %v)", first, last, gaps(dials))
	}
}

func gaps(ts []time.Time) []time.Duration {
	var out []time.Duration
	for i := 1; i < len(ts); i++ {
		out = append(out, ts[i].Sub(ts[i-1]).Round(time.Millisecond))
	}
	return out
}

// The other half of the fix: the device that has just got its coordinator back.
// Its new grant must be tried on the spot, not after the minutes of hold its old
// grant earned — and once the relay lets it in, the refusal is forgotten.
func TestRelayPoolRedialsAtOnceWhenANewGrantArrives(t *testing.T) {
	priv := testKey(7)
	relay := startGrantRelay(t, priv.Public())
	p := newRefusalTestPool(t, priv)
	p.SetGrant([]byte("a grant that has run out"))
	if err := p.DialHome(context.Background(), relay.addr); err != nil {
		t.Fatalf("dial home: %v", err)
	}
	waitHeld(t, p, relay.addr, 4) // hold is now 8 intervals

	fresh := []byte("the grant in the next netmap")
	relay.setAccept(fresh)
	n := relay.dialCount()
	p.SetGrant(fresh)
	if !relay.waitDial(n, 2*refusalTestEvery) {
		t.Fatalf("a new grant did not re-dial the home relay at once; the pool sat out the rest of an %v hold",
			p.refusalHold(4))
	}

	// Admitted and kept: no more dials, and the refusal is dropped once the
	// relay has answered a keepalive.
	deadline := time.Now().Add(3 * time.Second)
	for refusalCount(p) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("relay admitted the device but the pool still remembers it refusing (addrs=%v)", p.Addrs())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !bytes.Equal(relay.lastShown(), fresh) {
		t.Fatalf("relay last saw grant %q, want the fresh one", relay.lastShown())
	}
	settled := relay.dialCount()
	time.Sleep(5 * refusalTestEvery)
	if got := relay.dialCount(); got != settled {
		t.Fatalf("pool re-dialed %d more times after the relay admitted it", got-settled)
	}
	if addrs := p.Addrs(); len(addrs) != 1 || addrs[0] != relay.addr {
		t.Fatalf("pool lost the admitted link: %v", addrs)
	}
}

// Waking from sleep, or a changed network, re-dials the home relay at once —
// hold or no hold. The edge-certificate-rotation acceptance had devices back in
// ~35s through this path; a refusal hold must never stand in its way.
func TestRelayPoolResumeDialsThroughTheHold(t *testing.T) {
	priv := testKey(7)
	relay := startGrantRelay(t, priv.Public())
	p := newRefusalTestPool(t, priv)
	p.SetGrant([]byte("a grant that has run out"))
	if err := p.DialHome(context.Background(), relay.addr); err != nil {
		t.Fatalf("dial home: %v", err)
	}
	waitHeld(t, p, relay.addr, 3) // hold is now 4 intervals

	n := relay.dialCount()
	p.ResetLinks()
	if !relay.waitDial(n, 2*refusalTestEvery) {
		t.Fatal("ResetLinks waited out the refusal hold instead of re-dialing the home relay at once")
	}
}

// A relay that hangs up WITHOUT challenging has not refused anything: it is
// going down, or it is a proxy whose relay is. Those links must keep being
// re-dialed every sweep, so the device is back the moment the relay is.
func TestRelayPoolKeepsRedialingARelayThatHangsUpWithoutAsking(t *testing.T) {
	priv := testKey(7)
	relay := startGrantRelay(t, priv.Public())
	relay.mu.Lock()
	relay.hangUp = true
	relay.mu.Unlock()
	p := newRefusalTestPool(t, priv)
	if err := p.DialHome(context.Background(), relay.addr); err != nil {
		t.Fatalf("dial home: %v", err)
	}

	time.Sleep(12 * refusalTestEvery)
	if got := relay.dialCount(); got < 7 {
		t.Fatalf("relay saw %d links in 12 sweeps; a hang-up without a challenge was treated as a refusal", got)
	}
	if refusalCount(p) != 0 {
		t.Fatal("pool recorded a refusal from a relay that never asked for a grant")
	}

	// And the relay coming back is picked up within a sweep or two.
	relay.mu.Lock()
	relay.hangUp = false
	relay.accept = []byte("grant")
	relay.mu.Unlock()
	p.SetGrant([]byte("grant"))
	deadline := time.Now().Add(4 * refusalTestEvery)
	for {
		if addrs := p.Addrs(); len(addrs) == 1 && relay.lastShown() != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("relay came back but the pool did not relink within 4 sweeps (addrs=%v)", p.Addrs())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A dial that fails outright — connection refused while a relay restarts — is
// not a refusal either: the relay has said nothing about this device.
func TestRelayPoolDialFailureIsNotARefusal(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gone := ln.Addr().String()
	_ = ln.Close()

	p := newRefusalTestPool(t, testKey(7))
	if err := p.DialHome(context.Background(), gone); err == nil {
		t.Fatal("dial to a closed port succeeded")
	}
	time.Sleep(5 * refusalTestEvery)
	if refusalCount(p) != 0 {
		t.Fatal("a failed dial started a refusal hold")
	}
}

// The coordinator signs a fresh grant into every netmap it sends. When
// a relay refuses the device for a reason a fresh grant doesn't change, those
// netmaps must not become a re-dial each: the first new grant gets its try, and
// after the relay has refused that one too, only a grant with different terms
// (here: its scope) cuts the hold short.
func TestRelayPoolFreshGrantsDoNotRedialARelayThatRefusesThemAll(t *testing.T) {
	_, coordKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	priv := testKey(7)
	self := priv.Public()
	relay := startGrantRelay(t, self) // accepts nothing
	p := newRefusalTestPool(t, priv)

	p.SetGrant(signedGrant(t, coordKey, self, meshproto.RelayScopeSelfHosted, time.Hour))
	if err := p.DialHome(context.Background(), relay.addr); err != nil {
		t.Fatalf("dial home: %v", err)
	}
	waitHeld(t, p, relay.addr, 4)

	// The first new grant is tried at once, and refused too.
	n := relay.dialCount()
	p.SetGrant(signedGrant(t, coordKey, self, meshproto.RelayScopeSelfHosted, 2*time.Hour))
	if !relay.waitDial(n, 2*refusalTestEvery) {
		t.Fatal("the first new grant after a run of refusals was not tried at once")
	}
	waitHeld(t, p, relay.addr, 5) // hold is now 16 intervals

	// Another fresh grant with the same terms: nothing new to try.
	n = relay.dialCount()
	p.SetGrant(signedGrant(t, coordKey, self, meshproto.RelayScopeSelfHosted, 3*time.Hour))
	if relay.waitDial(n, 3*refusalTestEvery) {
		t.Fatal("a fresh grant with the same terms re-dialed a relay that had already refused a fresh one")
	}

	// A grant whose terms changed — the org's scope came back — is worth asking about.
	p.SetGrant(signedGrant(t, coordKey, self, meshproto.RelayScopeAll, 4*time.Hour))
	if !relay.waitDial(n, 2*refusalTestEvery) {
		t.Fatal("a grant with a different scope did not cut the hold short")
	}
}

// The same, with netmaps arriving faster than the pool sweeps — in a busy mesh
// they can — so nearly every refusal the pool sees is of a grant it has just
// replaced. That must not turn into a re-dial per sweep.
func TestRelayPoolFrequentNetmapsDoNotDefeatTheHold(t *testing.T) {
	_, coordKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	priv := testKey(7)
	self := priv.Public()
	relay := startGrantRelay(t, self) // accepts nothing
	p := newRefusalTestPool(t, priv)
	p.SetGrant(signedGrant(t, coordKey, self, meshproto.RelayScopeSelfHosted, time.Hour))
	if err := p.DialHome(context.Background(), relay.addr); err != nil {
		t.Fatalf("dial home: %v", err)
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 1; ; i++ {
			select {
			case <-stop:
				return
			case <-time.After(refusalTestEvery / 3):
			}
			p.SetGrant(signedGrant(t, coordKey, self, meshproto.RelayScopeSelfHosted, time.Hour+time.Duration(i)*time.Second))
		}
	}()
	time.Sleep(30 * refusalTestEvery)
	close(stop)
	<-done

	if got := relay.dialCount(); got > 10 {
		t.Fatalf("relay saw %d links in 30 sweeps while netmaps kept arriving; fresh grants it refuses as well defeated the hold (gaps %v)",
			got, gaps(relay.dialTimes()))
	}
}

// The netmap that brings a device its new grant can land while a link carrying
// the old one is being turned away. The new grant has not been tried yet, so the
// sweep re-dials with it straight away instead of starting a hold. The sweep is
// driven by hand here, so the order of events is exact.
func TestRelayPoolRetriesAtOnceWhenTheRefusedGrantWasAlreadyReplaced(t *testing.T) {
	priv := testKey(7)
	relay := startGrantRelay(t, priv.Public()) // refuses the old grant
	p := newRelayPoolTimed(priv.Public(), [meshproto.KeyLen]byte(priv), nil, slog.Default(), time.Hour, time.Hour)
	defer p.Close()
	p.SetGrant([]byte("old"))
	if err := p.DialHome(context.Background(), relay.addr); err != nil {
		t.Fatalf("dial home: %v", err)
	}
	p.mu.Lock()
	link := p.clients[relay.addr]
	p.mu.Unlock()
	select {
	case <-link.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("relay never turned the old grant away")
	}

	relay.setAccept([]byte("new"))
	p.SetGrant([]byte("new"))
	n := relay.dialCount()
	p.sweep()
	p.mu.Lock()
	held := p.heldLocked(relay.addr)
	p.mu.Unlock()
	if held {
		t.Fatal("the refusal of a grant already replaced started a hold against the new one")
	}
	if !relay.waitDial(n, 2*time.Second) {
		t.Fatal("the sweep did not re-dial with the new grant")
	}
	deadline := time.Now().Add(2 * time.Second)
	for !bytes.Equal(relay.lastShown(), []byte("new")) {
		if time.Now().After(deadline) {
			t.Fatalf("relay last saw grant %q, want the new one", relay.lastShown())
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// The hold doubles from one interval up to a cap and stays there: the device
// keeps asking every few minutes for as long as it runs. Production numbers.
func TestRelayPoolRefusalHoldIsCappedNotEndless(t *testing.T) {
	p := newRelayPoolTimed(meshproto.NodeKey{1}, [meshproto.KeyLen]byte{}, nil, slog.Default(), relayPingInterval, relayDeadAfter)
	defer p.Close()
	want := []time.Duration{15 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 5 * time.Minute, 5 * time.Minute}
	for i, w := range want {
		if got := p.refusalHold(i + 1); got != w {
			t.Fatalf("hold after refusal %d = %v, want %v", i+1, got, w)
		}
	}
	// A device refused all week long: still a 5-minute hold, never zero,
	// negative or overflowed.
	if got := p.refusalHold(7 * 24 * 12); got != 5*time.Minute {
		t.Fatalf("hold after a week of refusals = %v, want 5m", got)
	}
}
