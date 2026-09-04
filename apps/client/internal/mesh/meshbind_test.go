package mesh

import (
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

func testBind() *meshBind {
	return newMeshBind(meshproto.NodeKey{1}, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// fakeRelay records what the relay transport was asked to carry.
type fakeRelay struct {
	mu   sync.Mutex
	sent []relayed
}

type relayed struct {
	via string // which relay the bind chose ("" = our own home relay)
	dst meshproto.NodeKey
	pkt []byte
}

func (f *fakeRelay) Send(via string, dst meshproto.NodeKey, ciphertext []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, relayed{via: via, dst: dst, pkt: append([]byte(nil), ciphertext...)})
	return nil
}

// lastVia is the relay address the bind used for the most recent packet.
func (f *fakeRelay) lastVia() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sent) == 0 {
		return "<none>"
	}
	return f.sent[len(f.sent)-1].via
}

func (f *fakeRelay) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sent)
}

// fakePaths is a pathFinder with a fixed answer, recording retirements and the
// candidates the bind learns from DISCO sources.
type fakePaths struct {
	mu      sync.Mutex
	path    map[meshproto.DiscoKey]netip.AddrPort
	retired []meshproto.DiscoKey
	learned []learnedCand
}

type learnedCand struct {
	peer meshproto.DiscoKey
	ep   netip.AddrPort
}

func newFakePaths() *fakePaths {
	return &fakePaths{path: map[meshproto.DiscoKey]netip.AddrPort{}}
}

func (f *fakePaths) set(peer meshproto.DiscoKey, ap netip.AddrPort) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.path[peer] = ap
}

func (f *fakePaths) bestPath(peer meshproto.DiscoKey) (netip.AddrPort, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ap, ok := f.path[peer]
	return ap, ok
}

func (f *fakePaths) invalidatePath(peer meshproto.DiscoKey) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.path, peer)
	f.retired = append(f.retired, peer)
}

func (f *fakePaths) learnCandidate(peer meshproto.DiscoKey, ep netip.AddrPort) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.learned = append(f.learned, learnedCand{peer, ep})
}

// wgPacket is a minimally well-formed WireGuard datagram (type byte + three
// reserved zeros) so the magic socket's demux accepts it as data.
func wgPacket(payload string) []byte {
	return append([]byte{4, 0, 0, 0}, payload...)
}

// TestMeshBindReopenAfterClose is the regression for the DERP-only ping hang:
// wireguard-go opens/closes a bind repeatedly over a device's life, and a
// permanently-closed `closed` channel made every re-Opened receive() return
// ErrClosed immediately, so no inbound packet was ever read (both peers sent
// handshakes forever, neither received). Open must start a fresh receive cycle.
func TestMeshBindReopenAfterClose(t *testing.T) {
	b := testBind()

	// Simulate wireguard-go's open -> close -> open cycle during device setup.
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("first open: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	recv := fns[0]

	// A packet delivered after the reopen must reach the receive func — before the
	// fix this returned (0, net.ErrClosed).
	src := meshproto.NodeKey{2}
	want := []byte("wg-ciphertext")
	b.deliver(src, want)

	packets := [][]byte{make([]byte, 1500)}
	sizes := []int{0}
	eps := make([]conn.Endpoint, 1)
	n, err := recv(packets, sizes, eps)
	if err != nil {
		t.Fatalf("receive after reopen: %v", err)
	}
	if n != 1 {
		t.Fatalf("received %d packets, want 1", n)
	}
	if got := packets[0][:sizes[0]]; string(got) != string(want) {
		t.Fatalf("payload = %q, want %q", got, want)
	}
	if me, ok := eps[0].(*meshEndpoint); !ok || me.key != src {
		t.Fatalf("endpoint = %v, want meshEndpoint{key:%v}", eps[0], src)
	}
}

// TestMeshBindReceiveAfterFinalClose confirms a receive still unblocks with
// ErrClosed once the datapath tears the bind down for good (device shutdown).
func TestMeshBindReceiveAfterFinalClose(t *testing.T) {
	b := testBind()
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// receive must not block forever after Close — it returns net.ErrClosed so
	// wireguard-go's receive routine exits cleanly.
	done := make(chan error, 1)
	go func() {
		_, err := fns[0](makeBufs(), []int{0}, make([]conn.Endpoint, 1))
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("receive returned nil after Close, want ErrClosed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("receive blocked after Close")
	}
}

func makeBufs() [][]byte { return [][]byte{make([]byte, 1500)} }

// A peer with no validated direct path is reached over the relay; once the
// prober validates one, the very next packet goes straight out the direct socket
// — with no change to the WireGuard config or the endpoint object.
func TestMeshBindSendPrefersDirectPath(t *testing.T) {
	peerKey := meshproto.NodeKey{9}
	peerDisco := meshproto.DiscoKey{8}

	// The "peer" is a plain UDP socket we can read from.
	peerConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peerConn.Close()
	peerAddr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}),
		uint16(peerConn.LocalAddr().(*net.UDPAddr).Port))

	disco, _ := GenerateDiscoKey()
	ms, err := newMagicSock(disco, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer ms.Close()

	relay := &fakeRelay{}
	paths := newFakePaths()
	b := testBind()
	b.attach(relay)
	b.attachDirect(ms, paths)
	b.setPeers(WGConfig{Peers: []WGPeer{{PublicKey: peerKey, DiscoKey: peerDisco}}})
	ep := &meshEndpoint{b: b, key: peerKey}

	// No validated path yet -> relay.
	if err := b.Send([][]byte{wgPacket("via-relay")}, ep); err != nil {
		t.Fatalf("relay send: %v", err)
	}
	if relay.count() != 1 {
		t.Fatalf("relay carried %d packets, want 1", relay.count())
	}
	if _, ok := b.directPath(peerKey); ok {
		t.Fatal("directPath reported direct before any path was validated")
	}

	// Hole punching validates a path -> direct.
	paths.set(peerDisco, peerAddr)
	if err := b.Send([][]byte{wgPacket("via-direct")}, ep); err != nil {
		t.Fatalf("direct send: %v", err)
	}
	if relay.count() != 1 {
		t.Fatalf("relay carried %d packets after a direct path existed, want 1", relay.count())
	}
	_ = peerConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := peerConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("peer never received the direct packet: %v", err)
	}
	if got := string(buf[4:n]); got != "via-direct" {
		t.Fatalf("direct payload = %q, want via-direct", got)
	}
	if ap, ok := b.directPath(peerKey); !ok || ap != peerAddr {
		t.Fatalf("directPath = %s ok=%v, want %s", ap, ok, peerAddr)
	}
	// `wg show` (and the console) must show the punched endpoint, not the
	// synthetic relay stand-in.
	if got := ep.DstToString(); got != peerAddr.String() {
		t.Fatalf("DstToString = %q, want the direct endpoint %q", got, peerAddr)
	}
}

// A direct write that fails must not drop the packet: it retires the path and
// the packet still goes out over the relay.
func TestMeshBindDirectSendFallsBackToRelay(t *testing.T) {
	peerKey := meshproto.NodeKey{9}
	peerDisco := meshproto.DiscoKey{8}

	disco, _ := GenerateDiscoKey()
	ms, err := newMagicSock(disco, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	relay := &fakeRelay{}
	paths := newFakePaths()
	paths.set(peerDisco, netip.MustParseAddrPort("127.0.0.1:9"))
	b := testBind()
	b.attach(relay)
	b.attachDirect(ms, paths)
	b.setPeers(WGConfig{Peers: []WGPeer{{PublicKey: peerKey, DiscoKey: peerDisco}}})

	ms.Close() // the direct socket dies under us; every write now fails

	if err := b.Send([][]byte{wgPacket("payload")}, &meshEndpoint{b: b, key: peerKey}); err != nil {
		t.Fatalf("send should have fallen back to the relay, got %v", err)
	}
	if relay.count() != 1 {
		t.Fatalf("relay carried %d packets, want the fallback packet", relay.count())
	}
	paths.mu.Lock()
	retired := len(paths.retired)
	paths.mu.Unlock()
	if retired != 1 {
		t.Fatalf("dead path retired %d times, want 1", retired)
	}
	// With the path retired, the next send goes straight to the relay.
	if err := b.Send([][]byte{wgPacket("payload2")}, &meshEndpoint{b: b, key: peerKey}); err != nil {
		t.Fatalf("second send: %v", err)
	}
	if relay.count() != 2 {
		t.Fatalf("relay carried %d packets, want 2", relay.count())
	}
}

// While a full-tunnel exit node is engaged, direct paths stand down: a peer's
// public IP is inside the hijacked default route, so WireGuard's own transport
// would loop back through the tun. Only the relay is bypassed, so it carries.
func TestMeshBindDirectDisabledForExitNode(t *testing.T) {
	peerKey := meshproto.NodeKey{9}
	peerDisco := meshproto.DiscoKey{8}
	disco, _ := GenerateDiscoKey()
	ms, err := newMagicSock(disco, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer ms.Close()

	relay := &fakeRelay{}
	paths := newFakePaths()
	paths.set(peerDisco, netip.MustParseAddrPort("203.0.113.7:41641"))
	b := testBind()
	b.attach(relay)
	b.attachDirect(ms, paths)
	b.setPeers(WGConfig{Peers: []WGPeer{{PublicKey: peerKey, DiscoKey: peerDisco}}})

	b.setDirectEnabled(false)
	if _, ok := b.directPath(peerKey); ok {
		t.Fatal("direct path still offered while full-tunnelling")
	}
	if err := b.Send([][]byte{wgPacket("payload")}, &meshEndpoint{b: b, key: peerKey}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if relay.count() != 1 {
		t.Fatalf("relay carried %d packets, want 1", relay.count())
	}
	b.setDirectEnabled(true)
	if _, ok := b.directPath(peerKey); !ok {
		t.Fatal("direct path not restored after the exit node was cleared")
	}
}

// detachDirect (the control-plane session restarting) must leave a working
// relay-only bind behind.
func TestMeshBindDetachDirectFallsBackToRelay(t *testing.T) {
	peerKey := meshproto.NodeKey{9}
	peerDisco := meshproto.DiscoKey{8}
	disco, _ := GenerateDiscoKey()
	ms, err := newMagicSock(disco, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer ms.Close()

	relay := &fakeRelay{}
	paths := newFakePaths()
	paths.set(peerDisco, netip.MustParseAddrPort("203.0.113.7:41641"))
	b := testBind()
	b.attach(relay)
	b.attachDirect(ms, paths)
	b.setPeers(WGConfig{Peers: []WGPeer{{PublicKey: peerKey, DiscoKey: peerDisco}}})
	b.detachDirect()

	if err := b.Send([][]byte{wgPacket("payload")}, &meshEndpoint{b: b, key: peerKey}); err != nil {
		t.Fatalf("send after detach: %v", err)
	}
	if relay.count() != 1 {
		t.Fatalf("relay carried %d packets, want 1", relay.count())
	}
}

// An inbound direct packet from a peer we've exchanged DISCO with is handed to
// WireGuard KEYED to that peer, so replies keep choosing their transport per
// packet. One from an unattributable source is delivered pinned to its address,
// exactly as a plain UDP bind would.
func TestMeshBindDeliverDirectAttributesPeer(t *testing.T) {
	peerKey := meshproto.NodeKey{9}
	peerDisco := meshproto.DiscoKey{8}
	peerAddr := netip.MustParseAddrPort("198.51.100.4:41641")
	strangerAddr := netip.MustParseAddrPort("203.0.113.9:1234")

	disco, _ := GenerateDiscoKey()
	ms, err := newMagicSock(disco, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer ms.Close()
	b := testBind()
	b.attachDirect(ms, newFakePaths())
	b.setPeers(WGConfig{Peers: []WGPeer{{PublicKey: peerKey, DiscoKey: peerDisco}}})
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}

	b.noteDiscoSource(peerDisco, peerAddr) // the peer's DISCO reached us from here
	b.noteDiscoSource(meshproto.DiscoKey{7}, strangerAddr)
	b.dmu.Lock()
	tracked := len(b.srcOf)
	b.dmu.Unlock()
	if tracked != 1 {
		t.Fatalf("srcOf tracks %d addresses, want only the known peer's", tracked)
	}

	b.deliverDirect(peerAddr, wgPacket("from-peer"))
	ep := receiveOne(t, b)
	if ep.key != peerKey {
		t.Fatalf("endpoint key = %v, want the peer's %v", ep.key, peerKey)
	}
	if ep.direct.IsValid() {
		t.Fatalf("an attributed packet must not pin the endpoint, got %s", ep.direct)
	}

	b.deliverDirect(strangerAddr, wgPacket("from-stranger"))
	ep = receiveOne(t, b)
	if !ep.key.IsZero() || ep.direct != strangerAddr {
		t.Fatalf("unattributed endpoint = %v/%s, want pinned to %s", ep.key, ep.direct, strangerAddr)
	}

	// A peer that leaves the netmap stops being tracked.
	b.setPeers(WGConfig{})
	b.dmu.Lock()
	tracked = len(b.srcOf)
	b.dmu.Unlock()
	if tracked != 0 {
		t.Fatalf("srcOf kept %d addresses for peers no longer in the netmap", tracked)
	}
}

func receiveOne(t *testing.T, b *meshBind) *meshEndpoint {
	t.Helper()
	packets := [][]byte{make([]byte, 1500)}
	sizes := []int{0}
	eps := make([]conn.Endpoint, 1)
	n, err := b.receive(packets, sizes, eps)
	if err != nil || n != 1 {
		t.Fatalf("receive: n=%d err=%v", n, err)
	}
	me, ok := eps[0].(*meshEndpoint)
	if !ok {
		t.Fatalf("endpoint type %T, want *meshEndpoint", eps[0])
	}
	return me
}

// The whole direct data path over loopback sockets: node A probes B with DISCO,
// the prober validates the path, A's bind sends a WireGuard packet over it, and
// B's socket demultiplexes it into B's bind attributed to A. This is everything
// B3-3 adds except the tun device itself.
func TestDirectTransportRoundTrip(t *testing.T) {
	aDisco, _ := GenerateDiscoKey()
	bDisco, _ := GenerateDiscoKey()
	aKey := meshproto.NodeKey{0xa}
	bKey := meshproto.NodeKey{0xb}

	aSock, err := newMagicSock(aDisco, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer aSock.Close()
	bSock, err := newMagicSock(bDisco, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer bSock.Close()

	aRelay, bRelay := &fakeRelay{}, &fakeRelay{}
	aBind := newMeshBind(aKey, slog.Default())
	aBind.attach(aRelay)
	aBind.attachDirect(aSock, newDiscoProber(aSock, slog.Default()))
	aBind.setPeers(WGConfig{Peers: []WGPeer{{PublicKey: bKey, DiscoKey: bDisco.Public()}}})

	bBind := newMeshBind(bKey, slog.Default())
	bBind.attach(bRelay)
	bBind.attachDirect(bSock, newDiscoProber(bSock, slog.Default()))
	bBind.setPeers(WGConfig{Peers: []WGPeer{{PublicKey: aKey, DiscoKey: aDisco.Public()}}})
	if _, _, err := bBind.Open(0); err != nil {
		t.Fatal(err)
	}

	// A probes B's advertised endpoint; B auto-pongs and (as a side effect) learns
	// the address A's traffic will arrive from.
	prober := aBind.paths.(*discoProber)
	bAddr := loopback(bSock.LocalPort())
	prober.Probe([]Peer{{NodeKey: bKey, DiscoKey: bDisco.Public(), Endpoints: []netip.AddrPort{bAddr}}})

	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, ok := aBind.directPath(bKey); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("A never validated a direct path to B")
		}
		time.Sleep(10 * time.Millisecond)
	}

	want := wgPacket("wireguard-ciphertext")
	if err := aBind.Send([][]byte{want}, &meshEndpoint{b: aBind, key: bKey}); err != nil {
		t.Fatalf("A send: %v", err)
	}
	if aRelay.count() != 0 {
		t.Fatalf("A used the relay %d times despite a validated direct path", aRelay.count())
	}

	got := make(chan *meshEndpoint, 1)
	gotPkt := make(chan []byte, 1)
	go func() {
		packets := [][]byte{make([]byte, 1500)}
		sizes := []int{0}
		eps := make([]conn.Endpoint, 1)
		if n, err := bBind.receive(packets, sizes, eps); err == nil && n == 1 {
			gotPkt <- append([]byte(nil), packets[0][:sizes[0]]...)
			me, _ := eps[0].(*meshEndpoint)
			got <- me
		}
	}()
	select {
	case pkt := <-gotPkt:
		if string(pkt) != string(want) {
			t.Fatalf("B received %q, want %q", pkt, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("B never received the direct WireGuard packet")
	}
	me := <-got
	if me == nil || me.key != aKey {
		t.Fatalf("B attributed the packet to %v, want A (%v)", me, aKey)
	}
}

// The demux filter accepts WireGuard's four message types and rejects the noise
// that reaches a public UDP port.
func TestLooksLikeWireGuard(t *testing.T) {
	for _, typ := range []byte{1, 2, 3, 4} {
		if !looksLikeWireGuard([]byte{typ, 0, 0, 0, 0xff}) {
			t.Errorf("WireGuard message type %d rejected", typ)
		}
	}
	for name, pkt := range map[string][]byte{
		"too short":    {4, 0, 0},
		"bad type":     {5, 0, 0, 0},
		"zero type":    {0, 0, 0, 0},
		"reserved set": {4, 0, 1, 0},
		"random ascii": []byte("hello there"),
		"empty":        {},
	} {
		if looksLikeWireGuard(pkt) {
			t.Errorf("%s accepted as WireGuard", name)
		}
	}
}
