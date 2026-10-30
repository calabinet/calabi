package mesh

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	meshpb "github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

func schedulerFixture(n int) (*probeScheduler, []Peer) {
	p := &discoProber{pending: make(map[discoTxID]pendingProbe), paths: make(map[meshproto.DiscoKey]peerPath), learned: make(map[meshproto.DiscoKey]map[netip.AddrPort]time.Time)}
	s := newProbeScheduler(p, 50)
	peers := make([]Peer, n)
	for i := range peers {
		binary.LittleEndian.PutUint32(peers[i].DiscoKey[:], uint32(i+1))
		peers[i].Endpoints = []netip.AddrPort{
			netip.MustParseAddrPort("192.168.1.20:41641"),
			netip.MustParseAddrPort("10.2.0.20:41641"),
			netip.MustParseAddrPort("203.0.113.20:41641"),
		}
	}
	s.update(peers)
	return s, peers
}

// Exercise the production scheduler with 100/300/1000 visible peers and five
// active relationships. The sender simulates authenticated success only for
// one endpoint; the other two remain unreachable. Clock time is deterministic.
func TestProbeSchedulerCapacity(t *testing.T) {
	for _, n := range []int{100, 300, 1000} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			s, peers := schedulerFixture(n)
			now := time.Unix(1_700_000_000, 0)
			s.send = func(k meshproto.DiscoKey, ep netip.AddrPort) error {
				if ep == peers[0].Endpoints[0] {
					s.p.mu.Lock()
					s.p.paths[k] = peerPath{ep: ep, confirmed: now}
					s.p.mu.Unlock()
				}
				return nil
			}
			start := now
			for ; now.Sub(start) < 10*time.Minute; now = now.Add(time.Second) {
				s.step(now)
			}
			if got := s.sent.Load(); got != 0 {
				t.Fatalf("idle %d peers sent %d probes", n, got)
			}
			start = now
			for ; now.Sub(start) < 3*time.Minute; now = now.Add(20 * time.Millisecond) {
				for i := 0; i < 5; i++ {
					s.peers[peers[i].DiscoKey].active.Store(now.UnixNano())
				}
				s.step(now)
				if elapsed := now.Sub(start).Seconds(); float64(s.sent.Load()) > 50*elapsed+10.001 {
					t.Fatal("device rate budget exceeded")
				}
			}
			got := s.sent.Load()
			if got == 0 || float64(got)/180 > 5 {
				t.Fatalf("sparse traffic: %d probes over 180 seconds", got)
			}
			before := got
			now = now.Add(2 * probeIdle)
			for i := 0; i < 600; i++ {
				s.step(now)
				now = now.Add(time.Second)
			}
			if s.sent.Load() != before {
				t.Fatal("idle peers continued probing")
			}
			t.Logf("visible=%d candidates_per_peer=3 idle_600s=0 sparse_5_active_180s=%d (%.2f ping/s)", n, got, float64(got)/180)
		})
	}
}

func TestProbeSchedulerBudgetAndFairness(t *testing.T) {
	s, peers := schedulerFixture(1000)
	seen := map[meshproto.DiscoKey]bool{}
	s.send = func(k meshproto.DiscoKey, _ netip.AddrPort) error { seen[k] = true; return nil }
	now := time.Unix(1_700_000_000, 0)
	start := now
	for _, sp := range s.peers {
		sp.active.Store(now.UnixNano())
	}
	for ; now.Sub(start) < 30*time.Second; now = now.Add(20 * time.Millisecond) {
		s.step(now)
		if float64(s.sent.Load()) > 50*now.Sub(start).Seconds()+10.001 {
			t.Fatal("rate exceeded")
		}
	}
	if len(seen) != len(peers) {
		t.Fatalf("only %d/%d peers served", len(seen), len(peers))
	}
	if s.limited.Load() == 0 {
		t.Fatal("budget saturation was not reported")
	}
}

func TestProbeSchedulerMapDiffRemovalAndBackoff(t *testing.T) {
	s, peers := schedulerFixture(2)
	now := time.Unix(1_700_000_000, 0)
	s.send = func(meshproto.DiscoKey, netip.AddrPort) error { return nil }
	sp := s.peers[peers[0].DiscoKey]
	sp.active.Store(now.UnixNano())
	s.step(now)
	first := sp.candidates[0]
	// Endpoint ordering and grant-only map refreshes must preserve deadlines.
	peers[0].Endpoints[0], peers[0].Endpoints[2] = peers[0].Endpoints[2], peers[0].Endpoints[0]
	s.update(peers)
	if sp.candidates[0] != first {
		t.Fatal("identical address set reset backoff")
	}
	for i := 0; i < 1000; i++ {
		s.step(now.Add(time.Duration(i) * time.Millisecond))
	}
	if s.sent.Load() > 3 {
		t.Fatal("same-map events bypassed per-peer pacing")
	}
	k := peers[0].DiscoKey
	s.p.paths[k] = peerPath{ep: first.ep, confirmed: now}
	s.p.pending[discoTxID{1}] = pendingProbe{peer: k}
	s.p.learnCandidate(k, first.ep)
	s.update(peers[1:])
	if _, ok := s.p.paths[k]; ok || len(s.p.pending) != 0 || len(s.p.learned) != 0 {
		t.Fatal("removed peer retained transport state")
	}
	before := s.sent.Load()
	s.step(now.Add(time.Second))
	if before != s.sent.Load() {
		t.Fatal("removed peer sent another probe")
	}
}

func TestProbeSchedulerConfirmationShortensBackoff(t *testing.T) {
	s, peers := schedulerFixture(1)
	now := time.Unix(1_700_000_000, 0)
	sp := s.peers[peers[0].DiscoKey]
	sp.active.Store(now.UnixNano())
	sp.lastActive = now
	for i := range sp.candidates {
		sp.candidates[i].next = now.Add(5 * time.Minute)
	}
	ep := sp.candidates[0].ep
	s.p.paths[sp.key] = peerPath{ep: ep, confirmed: now}
	s.send = func(_ meshproto.DiscoKey, got netip.AddrPort) error {
		if got != ep {
			t.Fatal("wrong path")
		}
		return nil
	}
	s.step(now.Add(probeInterval))
	if s.sent.Load() != 1 {
		t.Fatal("newly confirmed path left on failed-candidate backoff")
	}
}

func TestProbeSchedulerRemoteRequestIsBounded(t *testing.T) {
	s, peers := schedulerFixture(1)
	s.send = func(meshproto.DiscoKey, netip.AddrPort) error { return nil }
	now := time.Unix(1_700_000_000, 0)
	s.requestAt(meshproto.DiscoKey{99}, now)
	s.step(now)
	if s.sent.Load() != 0 {
		t.Fatal("unknown requester activated discovery")
	}
	s.requestAt(peers[0].DiscoKey, now)
	s.step(now)
	if s.sent.Load() != 1 {
		t.Fatal("known authenticated request did not wake reverse discovery")
	}
	sp := s.peers[peers[0].DiscoKey]
	if sp.active.Load() != 0 {
		t.Fatal("probe was counted as business")
	}
	until := sp.remoteUntil
	for i := 1; i < 60; i++ {
		at := now.Add(time.Duration(i) * time.Second)
		s.requestAt(sp.key, at)
		if sp.remoteUntil != until {
			t.Fatal("repeated probe extended request window")
		}
		before := s.sent.Load()
		s.step(at)
		if i >= 5 && s.sent.Load() != before {
			t.Fatal("remote-only probing continued beyond five seconds")
		}
	}
	s.paused.Store(true)
	s.requestAt(sp.key, now.Add(time.Minute))
	before := s.sent.Load()
	s.step(now.Add(time.Minute))
	if before != s.sent.Load() {
		t.Fatal("paused direct transport emitted probes")
	}
}

func TestProbeSchedulerInheritsPausedTransport(t *testing.T) {
	key, _ := GenerateDiscoKey()
	ms, err := newMagicSock(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ms.Close()
	p := newDiscoProber(ms, nil)
	p.scheduler = newProbeScheduler(p, 50)
	b := newMeshBind(meshproto.NodeKey{1}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	b.setDirectEnabled(false)
	b.attachDirect(ms, p)
	defer b.detachDirect()
	if !p.scheduler.paused.Load() {
		t.Fatal("reconnected prober ignored existing full-tunnel suspension")
	}
	b.setDirectEnabled(true)
	if p.scheduler.paused.Load() {
		t.Fatal("prober did not resume after clearing exit device")
	}
}

func TestProbeSchedulerManyAdaptersKeepPublicAndLearnedEndpoints(t *testing.T) {
	s, peers := schedulerFixture(1)
	peers[0].Endpoints = nil
	for i := 1; i <= 60; i++ {
		peers[0].Endpoints = append(peers[0].Endpoints, netip.MustParseAddrPort(fmt.Sprintf("10.0.0.%d:41641", i)))
	}
	public := netip.MustParseAddrPort("203.0.113.1:41641")
	v6 := netip.MustParseAddrPort("[2001:db8::1]:41641")
	peers[0].Endpoints = append(peers[0].Endpoints, public, v6)
	s.update(peers)
	sp := s.peers[peers[0].DiscoKey]
	if len(sp.candidates) != probeAdvertisedLimit {
		t.Fatal("advertised candidate limit missing")
	}
	seen := map[netip.AddrPort]bool{}
	for _, c := range sp.candidates {
		seen[c.ep] = true
	}
	if !seen[public] || !seen[v6] {
		t.Fatal("virtual adapters hid the public candidates")
	}
	learned := netip.MustParseAddrPort("203.0.113.1:51000")
	s.p.learnCandidate(sp.key, learned)
	now := time.Now()
	sp.active.Store(now.UnixNano())
	s.send = func(meshproto.DiscoKey, netip.AddrPort) error { return nil }
	s.step(now)
	found := false
	for _, c := range sp.candidates {
		if c.ep == learned {
			found = true
		}
	}
	if !found {
		t.Fatal("advertised addresses left no room for symmetric NAT source learning")
	}
}

func TestProbeSchedulerRoutesAndAllowedInbound(t *testing.T) {
	s, peers := schedulerFixture(3)
	cfg := WGConfig{ExitNode: meshproto.NodeKey{3}, Peers: []WGPeer{
		{PublicKey: meshproto.NodeKey{1}, DiscoKey: peers[0].DiscoKey, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")}},
		{PublicKey: meshproto.NodeKey{2}, DiscoKey: peers[1].DiscoKey, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.96.0.0/24")}},
		{PublicKey: meshproto.NodeKey{3}, DiscoKey: peers[2].DiscoKey, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}},
	}}
	s.setRoutes(cfg)
	inner := &fakeTUN{}
	f := &PacketFilter{}
	f.SetRules(true, nil)
	ft := newFilteredTUN(context.Background(), inner, f, nil, nil)
	ft.probes.Store(s)
	packet := ipv4("100.64.0.2", protoTCP, 80, 0)
	_, _ = ft.Write([][]byte{packet}, 0)
	if s.peers[peers[0].DiscoKey].active.Load() != 0 {
		t.Fatal("denied inbound packet activated discovery")
	}
	f.SetRules(false, nil)
	_, _ = ft.Write([][]byte{packet}, 0)
	if s.peers[peers[0].DiscoKey].active.Load() == 0 {
		t.Fatal("allowed inbound did not activate peer")
	}
	s.observe(netip.MustParseAddr("100.96.0.8"))
	s.observe(netip.MustParseAddr("8.8.8.8"))
	if s.peers[peers[1].DiscoKey].active.Load() == 0 || s.peers[peers[2].DiscoKey].active.Load() == 0 {
		t.Fatal("subnet or exit route not activated")
	}
}

// Real UDP + DISCO authentication, with no kernel TUN or administrator rights.
func TestProbeSchedulerRealUDP(t *testing.T) {
	aKey, _ := GenerateDiscoKey()
	bKey, _ := GenerateDiscoKey()
	a, err := newMagicSock(aKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := newMagicSock(bKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	p := newDiscoProber(a, nil)
	s := newProbeScheduler(p, 50)
	p.scheduler = s
	peer := Peer{DiscoKey: bKey.Public(), Endpoints: []netip.AddrPort{loopback(b.LocalPort())}}
	p.Probe([]Peer{peer})
	if p.ms.txPackets.Load() != 0 {
		t.Fatal("map alone sent probes")
	}
	s.peers[peer.DiscoKey].active.Store(time.Now().UnixNano())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); p.run(ctx, probeInterval, nil) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if ep, ok := p.bestPath(peer.DiscoKey); ok {
			if ep != peer.Endpoints[0] {
				t.Fatal("wrong path")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("active peer did not authenticate a direct path")
}

// The real controller must install the new scheduler, clear idle WG keepalive,
// and connect activity to its TUN wrapper. This catches a disconnected feature
// whose unit tests pass but whose default user path still uses legacy probing.
func TestControllerInstallsAdaptiveProbing(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy_%v", legacy), func(t *testing.T) { testControllerProbeMode(t, legacy) })
	}
}

func testControllerProbeMode(t *testing.T, legacy bool) {
	t.Setenv("CALABI_MESH_LEGACY_PROBING", "")
	if legacy {
		t.Setenv("CALABI_MESH_LEGACY_PROBING", "1")
	}
	t.Setenv("CALABI_MESH_KEEP_PEER_KEEPALIVE", "")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	d, err := NewWGDatapathOnTUN(tuntest.NewChannelTUN().TUN(), &recordingRouting{}, testKey(1), "127.0.0.1:1", logger)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	peerDisco, _ := GenerateDiscoKey()
	f := &fakeCoord{
		reg: &meshpb.RegisterNodeResponse{NodeId: 1, OverlayAddr: "100.64.0.1"},
		netmaps: []*meshpb.NetMap{{Self: &meshpb.Peer{NodeId: 1, NodeKey: testKey(1).Public().String(), OverlayAddr: "100.64.0.1"},
			Peers: []*meshpb.Peer{{NodeId: 2, NodeKey: testKey(2).Public().String(), DiscoKey: peerDisco.Public().String(), OverlayAddr: "100.64.0.2", AllowedIps: []string{"100.64.0.2/32"}, Endpoints: []string{"127.0.0.1:9"}}}}},
	}
	ctrl := &Controller{Coord: dialFake(t, f), Datapath: d, Params: RegisterParams{AuthKey: "k", NodeKey: testKey(1).Public(), NodePrivate: testKey(1)}, Logger: logger}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- ctrl.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("controller did not stop")
		}
	}()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		s := d.ftun.probes.Load()
		if legacy {
			dump, err := d.dev.IpcGet()
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(dump, "public_key=") {
				if s != nil || !strings.Contains(dump, "persistent_keepalive_interval=25") {
					t.Fatal("legacy rollback did not restore original behavior")
				}
				return
			}
		}
		if s != nil && s.routes.Load() != nil {
			dump, err := d.dev.IpcGet()
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(dump, "public_key=") {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			if strings.Contains(dump, "persistent_keepalive_interval=25") {
				t.Fatal("idle per-peer keepalive remained enabled")
			}
			if s.sent.Load() != 0 {
				t.Fatal("idle map triggered discovery")
			}
			// Allowed inner traffic, with the inbound filter disabled, must wake
			// this actual controller-created scheduler.
			s.observe(netip.MustParseAddr("100.64.0.2"))
			s.mu.Lock()
			active := s.peers[peerDisco.Public()].active.Load()
			s.mu.Unlock()
			if active == 0 {
				t.Fatal("real session route was not installed")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("controller did not install adaptive probing on the default path")
}

// A complete WireGuard path on in-memory TUN devices, real UDP sockets and a
// real relay hub. No privileged network changes or physical devices required.
func TestAdaptiveWireGuardBusinessRoundTrip(t *testing.T) {
	for _, available := range []bool{true, false} {
		t.Run(fmt.Sprintf("relay_available_%v", available), func(t *testing.T) { testAdaptiveWireGuardBusinessRoundTrip(t, available) })
	}
}

func testAdaptiveWireGuardBusinessRoundTrip(t *testing.T, relayAvailable bool) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	relay := "127.0.0.1:1"
	if relayAvailable {
		relay = startSniffingRelay(t, tls.Certificate{}).addr
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var devices [2]*WGDatapath
	var channels [2]*tuntest.ChannelTUN
	var probers [2]*discoProber
	var sockets [2]*magicSock
	var keys [2]PrivateKey
	var disco [2]DiscoPrivateKey
	addresses := [2]netip.Addr{netip.MustParseAddr("100.64.0.11"), netip.MustParseAddr("100.64.0.12")}
	done := make(chan struct{}, 2)
	for i := 0; i < 2; i++ {
		keys[i], _ = GenerateKey()
		disco[i], _ = GenerateDiscoKey()
		channels[i] = tuntest.NewChannelTUN()
		d, err := NewWGDatapathOnTUN(channels[i].TUN(), &recordingRouting{}, keys[i], relay, logger)
		if err != nil {
			t.Fatal(err)
		}
		devices[i] = d
		defer d.Close()
		ms, err := newMagicSock(disco[i], nil)
		if err != nil {
			t.Fatal(err)
		}
		sockets[i] = ms
		defer ms.Close()
		p := newDiscoProber(ms, nil)
		probers[i] = p
		p.scheduler = newProbeScheduler(p, 50)
		d.attachDirect(ms, p)
	}
	for i := 0; i < 2; i++ {
		j := 1 - i
		p := probers[i]
		p.Probe([]Peer{{DiscoKey: disco[j].Public(), Endpoints: []netip.AddrPort{loopback(sockets[j].LocalPort())}}})
		cfg := WGConfig{NodeKey: keys[i].Public(), OverlayAddr: addresses[i], SelfRelay: relay, RelayByRegion: map[string]string{"test": relay}, Peers: []WGPeer{{PublicKey: keys[j].Public(), DiscoKey: disco[j].Public(), DERPHome: "test", AllowedIPs: []netip.Prefix{netip.PrefixFrom(addresses[j], 32)}}}}
		if err := devices[i].SetConfig(cfg); err != nil {
			t.Fatal(err)
		}
		go func() { defer func() { done <- struct{}{} }(); p.run(ctx, probeInterval, nil) }()
	}
	defer func() { cancel(); <-done; <-done }()
	transmit := func(from, to int) {
		t.Helper()
		pkt := tuntest.Ping(addresses[to], addresses[from])
		select {
		case channels[from].Outbound <- pkt:
		case <-time.After(3 * time.Second):
			t.Fatal("outbound TUN stalled")
		}
		select {
		case got := <-channels[to].Inbound:
			if string(got) != string(pkt) {
				t.Fatal("inner packet changed")
			}
		case <-time.After(10 * time.Second):
			t.Fatal("business packet did not cross WireGuard")
		}
	}
	transmit(0, 1)
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, a := probers[0].bestPath(disco[1].Public())
		_, b := probers[1].bestPath(disco[0].Public())
		if a && b {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("business did not establish bidirectional direct paths")
		}
		time.Sleep(10 * time.Millisecond)
	}
	transmit(1, 0)
	// Targeted keepalive changes and an identical map must preserve established
	// WireGuard traffic counters, rather than replacing the entire peer set.
	key := keys[1].Public()
	beforeKeepalive := devices[0].Snapshot().Peers[0]
	if beforeKeepalive.RxBytes == 0 || beforeKeepalive.TxBytes == 0 {
		t.Fatal("no baseline traffic for keepalive test")
	}
	if err := devices[0].SetPeerKeepalive(key, 25*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := devices[0].SetConfig(WGConfig{NodeKey: keys[0].Public(), OverlayAddr: addresses[0], SelfRelay: relay, RelayByRegion: map[string]string{"test": relay}, Peers: []WGPeer{{PublicKey: key, DiscoKey: disco[1].Public(), DERPHome: "test", AllowedIPs: []netip.Prefix{netip.PrefixFrom(addresses[1], 32)}}}}); err != nil {
		t.Fatal(err)
	}
	if err := devices[0].SetPeerKeepalive(key, 0); err != nil {
		t.Fatal(err)
	}
	afterKeepalive := devices[0].Snapshot().Peers[0]
	if afterKeepalive.RxBytes < beforeKeepalive.RxBytes || afterKeepalive.TxBytes < beforeKeepalive.TxBytes || afterKeepalive.LastHandshakeSec != beforeKeepalive.LastHandshakeSec {
		t.Fatal("keepalive update reset counters or handshake")
	}
	if err := devices[0].SetPeerKeepalive(meshproto.NodeKey{99}, 0); err == nil {
		t.Fatal("unknown peer accepted keepalive override")
	}
	if devices[1].Snapshot().Datapath.TxDirect == 0 {
		t.Fatal("validated path was not used for business")
	}
	if !relayAvailable {
		return
	}
	// Stale direct paths must fall back through the same encrypted relay link.
	for i, p := range probers {
		p.scheduler.paused.Store(true)
		p.invalidatePath(disco[1-i].Public())
	}
	before := devices[0].Snapshot().Datapath.TxRelay
	transmit(0, 1)
	if devices[0].Snapshot().Datapath.TxRelay <= before {
		t.Fatal("no relay fallback after path invalidation")
	}
}

func BenchmarkProbeSchedulerObserve(b *testing.B) {
	s, peers := schedulerFixture(1000)
	addr := netip.MustParseAddr("100.64.0.2")
	s.setRoutes(WGConfig{Peers: []WGPeer{{DiscoKey: peers[0].DiscoKey, AllowedIPs: []netip.Prefix{netip.PrefixFrom(addr, 32)}}}})
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		s.observe(addr)
	}
}

func BenchmarkProbeSchedulerIdle1000(b *testing.B) {
	s, _ := schedulerFixture(1000)
	now := time.Unix(1_700_000_000, 0)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		s.step(now)
	}
}
