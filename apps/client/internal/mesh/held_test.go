package mesh

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/device"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

// A pool with no link to send on says so; it is not "closed" until it is.
// net.ErrClosed here is what WireGuard printed as "use of closed network
// connection" at the start of every self-hosted device.
func TestRelayPoolWithNoLinkSaysSoRatherThanClosed(t *testing.T) {
	p := newRelayPool(meshproto.NodeKey{1}, [meshproto.KeyLen]byte{}, nil, slog.Default())
	err := p.Send("", meshproto.NodeKey{2}, []byte("x"))
	if !errors.Is(err, errNoRelayLink) || errors.Is(err, net.ErrClosed) {
		t.Fatalf("send with no link = %v, want errNoRelayLink", err)
	}
	_ = p.Close()
	if err := p.Send("", meshproto.NodeKey{2}, []byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("send after Close = %v, want net.ErrClosed", err)
	}
}

// The start of a self-hosted device: the home relay only comes with the first
// netmap, and WireGuard's first handshake goes out before its link is up. That
// packet used to be lost (and WireGuard waited 5 seconds to try again); now it
// is held, and goes out on the link as soon as it comes up.
func TestAPacketSentBeforeTheFirstRelayLinkGoesOutWhenItComesUp(t *testing.T) {
	relay := startFakeRelay(t)
	self, peer := meshproto.NodeKey{1}, meshproto.NodeKey{2}
	bind := newMeshBind(self, nil, slog.Default())
	pool := newRelayPool(self, [meshproto.KeyLen]byte{}, nil, slog.Default())
	defer pool.Close()
	pool.setOnLinkUp(func(string) { bind.retryHeld() })
	bind.attach(pool)

	if err := bind.Send([][]byte{[]byte("handshake initiation")}, &meshEndpoint{b: bind, key: peer}); err != nil {
		t.Fatalf("send before any relay link = %v, want it held", err)
	}
	if relay.forwarded() != 0 {
		t.Fatal("the relay got a packet before it was even known")
	}

	pool.Reconcile(relay.addr, nil) // the first netmap names the home relay
	if got := relay.waitForward(t); got != peer {
		t.Fatalf("relay forwarded to %v, want the peer", got)
	}
	if n := bind.txRelayErr.Load(); n != 0 {
		t.Fatalf("relay send errors = %d, want 0", n)
	}
}

// recordingRelay is a relay link that is up: it records what it relays.
type recordingRelay struct {
	mu   sync.Mutex
	sent []string
}

func (r *recordingRelay) Send(_ string, _ meshproto.NodeKey, b []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, string(b))
	return nil
}

func (r *recordingRelay) got() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.sent...)
}

func (*recordingRelay) TxDropped() uint64                  { return 0 }
func (*recordingRelay) TxBlocked() time.Duration           { return 0 }
func (*recordingRelay) TxSockBuf() int                     { return 0 }
func (*recordingRelay) TxRate() float64                    { return 0 }
func (*recordingRelay) RTTTo(string) (time.Duration, bool) { return 0, false }

// noLinkSender is a relay pool with no link up.
type noLinkSender struct{ recordingRelay }

func (*noLinkSender) Send(string, meshproto.NodeKey, []byte) error { return errNoRelayLink }

// Held packets are copies (WireGuard reuses its buffers), go out in order, and
// are bounded: heldPerPeer a peer, heldTTL old. What is pushed out or expires
// counts as a relay send error — a drop this datapath chose is reported.
func TestHeldPacketsAreCopiedOrderedAndBounded(t *testing.T) {
	peer := meshproto.NodeKey{2}
	bind := newMeshBind(meshproto.NodeKey{1}, nil, slog.Default())
	bind.attach(&noLinkSender{})

	buf := []byte("p0")
	for i := 0; i < heldPerPeer+2; i++ {
		copy(buf, fmt.Sprintf("p%d", i))
		if err := bind.Send([][]byte{buf}, &meshEndpoint{b: bind, key: peer}); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	if n := bind.txRelayErr.Load(); n != 2 {
		t.Fatalf("relay send errors = %d, want the 2 pushed out", n)
	}

	up := &recordingRelay{}
	bind.attach(up)
	bind.retryHeld()
	var want []string
	for i := 2; i < heldPerPeer+2; i++ {
		want = append(want, fmt.Sprintf("p%d", i))
	}
	if got := up.got(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("sent %q, want %q", got, want)
	}

	bind.attach(&noLinkSender{})
	bind.hold(peer, [][]byte{[]byte("old")}, time.Now().Add(-heldTTL-time.Second))
	up = &recordingRelay{}
	bind.attach(up)
	bind.retryHeld()
	if got := up.got(); len(got) != 0 {
		t.Fatalf("an expired packet was sent: %q", got)
	}
	if n := bind.txRelayErr.Load(); n != 3 {
		t.Fatalf("relay send errors = %d, want the expired one counted too", n)
	}
}

// A retry that still finds no path keeps each packet's age: retrying never
// extends a held packet's life.
func TestRetryingKeepsAHeldPacketsAge(t *testing.T) {
	peer := meshproto.NodeKey{2}
	bind := newMeshBind(meshproto.NodeKey{1}, nil, slog.Default())
	bind.attach(&noLinkSender{})
	at := time.Now().Add(-time.Second)
	bind.hold(peer, [][]byte{[]byte("x")}, at)
	bind.retryHeld()
	bind.hmu.Lock()
	q := bind.held[peer]
	bind.hmu.Unlock()
	if len(q) != 1 || !q[0].at.Equal(at) {
		t.Fatalf("held after a fruitless retry = %+v, want the one packet at its first time", q)
	}
}

// The prober tells the bind of a direct path it did not have — once, not on
// every pong that refreshes it — and outside its lock: the bind's retry asks
// bestPath, which takes that lock.
func TestProberReportsANewDirectPathOnceOutsideItsLock(t *testing.T) {
	p := &discoProber{
		pending: make(map[discoTxID]pendingProbe),
		paths:   make(map[meshproto.DiscoKey]peerPath),
		learned: make(map[meshproto.DiscoKey]map[netip.AddrPort]time.Time),
	}
	peer := meshproto.DiscoKey{7}
	ep := netip.MustParseAddrPort("192.0.2.1:41641")
	calls := 0
	p.setOnPathFound(func() {
		calls++
		p.bestPath(peer) // deadlocks if called under p.mu
	})
	pong := func(tx byte) {
		var id discoTxID
		id[0] = tx
		p.mu.Lock()
		p.pending[id] = pendingProbe{peer: peer, ep: ep, sent: time.Now()}
		p.mu.Unlock()
		done := make(chan struct{})
		go func() { p.onPong(peer, id, ep); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("onPong deadlocked: the callback ran under the prober's lock")
		}
	}
	pong(1)
	pong(2) // the same path again
	if calls != 1 {
		t.Fatalf("callback ran %d times, want once for the one new path", calls)
	}
}

// wireguard-go's log lines reach the daemon's log. "No relay link yet" is one
// this datapath handles (the packet is held), so it is debug, not an error;
// everything else stays an error.
func TestWireGuardLogsGoToTheDaemonLog(t *testing.T) {
	var out bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelDebug}))
	l := wgLogger(logger, device.LogLevelError)

	l.Errorf("%v - Failed to send handshake initiation: %v", "peer(x)", fmt.Errorf("send: %w", errNoRelayLink))
	l.Errorf("%v - Failed to send data packets: %v", "peer(x)", errors.New("boom"))
	l.Verbosef("%v - Sending handshake initiation", "peer(x)")

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("log = %q, want two lines (verbose is off)", out.String())
	}
	if !strings.Contains(lines[0], "level=DEBUG") || !strings.Contains(lines[0], "handshake initiation") {
		t.Errorf("no-relay-link line = %q, want debug", lines[0])
	}
	if !strings.Contains(lines[1], "level=ERROR") || !strings.Contains(lines[1], "boom") {
		t.Errorf("other error = %q, want error", lines[1])
	}
}

// authRelay authenticates like pkg/relay's hub: it challenges each link and
// discards every frame until the proof — data packets included — and only then
// carries packets and answers Pings. admitAfter is how long it takes over a
// proof, so a test can send into the window between "connected" and "admitted".
type authRelay struct {
	addr       string
	self       meshproto.NodeKey
	admitAfter time.Duration

	mu        sync.Mutex
	forwarded []string // payloads carried after admission
	discarded int      // data packets that arrived before the proof
}

func startAuthRelay(t *testing.T, self meshproto.NodeKey, admitAfter time.Duration) *authRelay {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &authRelay{addr: ln.Addr().String(), self: self, admitAfter: admitAfter}
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

func (s *authRelay) serve(conn net.Conn) {
	defer conn.Close()
	if typ, _, err := meshproto.ReadDERPFrame(conn); err != nil || typ != meshproto.DERPFrameClientInfo {
		return
	}
	ch, ephPriv, err := meshproto.NewDERPAuthChallenge()
	if err != nil || meshproto.WriteDERPFrame(conn, meshproto.DERPFrameAuthChallenge, ch.Encode()) != nil {
		return
	}
	for {
		typ, p, err := meshproto.ReadDERPFrame(conn)
		if err != nil {
			return
		}
		if typ == meshproto.DERPFrameSendPacket {
			s.mu.Lock()
			s.discarded++
			s.mu.Unlock()
		}
		if typ != meshproto.DERPFrameAuthProof {
			continue
		}
		if _, err := meshproto.OpenDERPAuthProof(ch, ephPriv, s.self, p); err != nil {
			return
		}
		break
	}
	time.Sleep(s.admitAfter)
	for {
		typ, p, err := meshproto.ReadDERPFrame(conn)
		if err != nil {
			return
		}
		switch typ {
		case meshproto.DERPFramePing:
			_ = meshproto.WriteDERPFrame(conn, meshproto.DERPFramePong, p)
		case meshproto.DERPFrameSendPacket:
			if _, ct, err := meshproto.SplitPacket(p); err == nil {
				s.mu.Lock()
				s.forwarded = append(s.forwarded, string(ct))
				s.mu.Unlock()
			}
		}
	}
}

func (s *authRelay) state() ([]string, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.forwarded...), s.discarded
}

// The start of a self-hosted device against a relay that authenticates: the
// link is connected before the relay has admitted it, and a relay discards what
// arrives before the proof. The first handshake — sent before the link existed —
// and a packet sent while it was connected but not yet admitted must both be
// held and go out once the relay admits the device, not be lost in between.
func TestTheFirstHandshakeWaitsForTheRelayToAdmitTheDevice(t *testing.T) {
	priv := testKey(9)
	self, peer := priv.Public(), meshproto.NodeKey{2}
	relay := startAuthRelay(t, self, 300*time.Millisecond)
	bind := newMeshBind(self, nil, slog.Default())
	pool := newRelayPool(self, [meshproto.KeyLen]byte(priv), nil, slog.Default())
	defer pool.Close()
	pool.setOnLinkUp(func(string) { bind.retryHeld() })
	bind.attach(pool)
	pool.SetGrant([]byte("grant"))
	ep := &meshEndpoint{b: bind, key: peer}

	if err := bind.Send([][]byte{[]byte("initiation")}, ep); err != nil {
		t.Fatalf("send before any link: %v", err)
	}
	pool.Reconcile(relay.addr, nil) // the first netmap names the home relay
	deadline := time.Now().Add(3 * time.Second)
	for len(pool.Addrs()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the home relay was never dialed")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := bind.Send([][]byte{[]byte("while connecting")}, ep); err != nil {
		t.Fatalf("send while the relay admits the link: %v", err)
	}

	for {
		got, discarded := relay.state()
		if discarded != 0 {
			t.Fatalf("%d packet(s) went to the relay before it admitted the device, and were lost", discarded)
		}
		if strings.Join(got, ",") == "initiation,while connecting" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("relay carried %q, want both packets once the device was admitted", got)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
