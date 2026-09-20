package mesh

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	meshpb "github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
)

// The meter's whole job is to turn bytes that already went out over the relay
// into a wait on the NEXT tun read. Sizing: 1 MiB/s with a 2 MiB burst
// (sustained-only path), charged 3 MiB, leaves 1 MiB to pay for = ~1 s. Half a
// second of that is enough to tell a real wait from no wait at all without
// making the test slow.
func TestRelayMeter_SettlePaysForWhatTheBindCharged(t *testing.T) {
	m := &relayMeter{}
	m.SetRelayRate(1<<20, 0)

	m.charge(3 << 20)
	start := time.Now()
	m.settle(context.Background())
	waited := time.Since(start)

	if waited < 500*time.Millisecond {
		t.Fatalf("3 MiB against a 1 MiB/s rate with a 2 MiB burst must wait ~1s; waited %v", waited)
	}
	if got, _ := m.stats(); got != 3<<20 {
		t.Fatalf("charged = %d, want %d", got, 3<<20)
	}
	if _, micros := m.stats(); micros <= 0 {
		t.Fatal("the wait must be recorded — it is how 'why is my mesh slow' gets answered")
	}
	// The debt is settled; a second settle is free.
	start = time.Now()
	m.settle(context.Background())
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Fatalf("nothing outstanding, settle must return at once; took %v", d)
	}
}

// No allowance = no limiting, which is what every client gets from a
// coordinator that does not send one (and every client until one does).
func TestRelayMeter_NoRateIsFree(t *testing.T) {
	var nilMeter *relayMeter
	nilMeter.charge(1 << 20)
	nilMeter.settle(context.Background()) // must not panic

	m := &relayMeter{}
	m.charge(64 << 20)
	start := time.Now()
	m.settle(context.Background())
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Fatalf("no rate installed must not throttle; waited %v", d)
	}
	if got, _ := m.stats(); got != 0 {
		t.Fatalf("with no rate installed there is nothing to account; charged = %d", got)
	}
}

// A datapath shutting down must not be stuck inside settle. The bytes are
// forgiven rather than carried: the only ctx that cancels here is teardown.
func TestRelayMeter_SettleReleasesOnCancel(t *testing.T) {
	m := &relayMeter{}
	m.SetRelayRate(1<<10, 0) // 1 KiB/s: paying 8 MiB would take hours
	m.charge(8 << 20)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.settle(ctx); close(done) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("settle must return when its context is cancelled")
	}
}

// Lowering the rate to zero (an allowance being withdrawn) must take effect,
// and must not leave a debt that blocks forever.
func TestRelayMeter_RateCanBeRemoved(t *testing.T) {
	m := &relayMeter{}
	m.SetRelayRate(1<<20, 0)
	m.charge(8 << 20)
	m.SetRelayRate(0, 0)

	start := time.Now()
	m.settle(context.Background())
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Fatalf("a withdrawn allowance must stop throttling; waited %v", d)
	}
}

// THE load-bearing one: only RELAYED bytes may be charged. Direct paths run on
// the user's own network and cost the platform nothing — charging them would
// throttle traffic we have no business throttling, and the tun-side brake
// holds up every peer, so the error would not even stay local to that peer.
func TestRelayMeter_ChargesRelayedTrafficOnly(t *testing.T) {
	peerKey := meshproto.NodeKey{9}
	peerDisco := meshproto.DiscoKey{8}

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

	meter := &relayMeter{}
	meter.SetRelayRate(1<<30, 0) // huge: we are counting, not throttling
	b := newMeshBind(meshproto.NodeKey{1}, meter, slog.New(slog.NewTextHandler(io.Discard, nil)))
	b.attach(&fakeRelay{})
	paths := newFakePaths()
	b.attachDirect(ms, paths)
	b.setPeers(WGConfig{Peers: []WGPeer{{PublicKey: peerKey, DiscoKey: peerDisco}}})
	ep := &meshEndpoint{b: b, key: peerKey}

	// No validated direct path yet ⇒ this one takes the relay and is charged.
	relayed := wgPacket("via-relay")
	if err := b.Send([][]byte{relayed}, ep); err != nil {
		t.Fatalf("relay send: %v", err)
	}
	charged, _ := meter.stats()
	if charged != uint64(len(relayed)) {
		t.Fatalf("relayed packet must be charged its ciphertext length: charged %d, want %d",
			charged, len(relayed))
	}

	// Validate a direct path; the next send takes it and must NOT be charged.
	paths.set(peerDisco, peerAddr)
	if err := b.Send([][]byte{wgPacket("via-direct")}, ep); err != nil {
		t.Fatalf("direct send: %v", err)
	}
	if b.txDirect.Load() == 0 {
		t.Fatal("test setup: the second packet was supposed to go direct")
	}
	after, _ := meter.stats()
	if after != charged {
		t.Fatalf("a direct packet must cost nothing: charged went %d → %d", charged, after)
	}
}

// The allowance has to survive the whole way from the coordinator's netmap to
// the buckets, through two conversions. A break anywhere in that chain leaves
// the client un-paced and the relay dropping — which looks exactly like a
// network problem, so it is worth pinning end to end rather than per hop.
func TestRelayRate_ArrivesFromTheNetmap(t *testing.T) {
	pb := &meshpb.NetMap{
		Self: &meshpb.Peer{
			NodeId: 1, NodeKey: keyB64(1),
			OverlayAddr: "100.64.0.1", AllowedIps: []string{"100.64.0.1/32"},
		},
		RelayBandwidthKbps:      5120,  // 5 Mbps sustained
		RelayBandwidthBurstKbps: 20480, // 20 Mbps peak
	}
	nm, err := FromNetMap(pb)
	if err != nil {
		t.Fatalf("FromNetMap: %v", err)
	}
	if nm.RelayBandwidthKbps != 5120 || nm.RelayBandwidthBurstKbps != 20480 {
		t.Fatalf("netmap decode lost the rate: %d/%d", nm.RelayBandwidthKbps, nm.RelayBandwidthBurstKbps)
	}
	cfg := BuildWGConfig(nm)
	if cfg.RelayBandwidthKbps != 5120 || cfg.RelayBandwidthBurstKbps != 20480 {
		t.Fatalf("config build lost the rate: %d/%d", cfg.RelayBandwidthKbps, cfg.RelayBandwidthBurstKbps)
	}
	// ×1024/8, matching the edge — 5120 kbps is 655360 B/s, not 640000.
	if got := relayRateBytesPerSec(cfg.RelayBandwidthKbps); got != 655360 {
		t.Fatalf("kbps→bytes/sec = %d, want 655360 (×1024/8, the same convention the relay meters with)", got)
	}
}

// An older coordinator sends nothing, and a self-hosted one sends nothing on
// purpose. Both must read as "no self-limit", never as "limit zero".
func TestRelayRate_AbsentFromNetmapMeansNoLimit(t *testing.T) {
	nm, err := FromNetMap(&meshpb.NetMap{
		Self: &meshpb.Peer{
			NodeId: 1, NodeKey: keyB64(1),
			OverlayAddr: "100.64.0.1", AllowedIps: []string{"100.64.0.1/32"},
		},
	})
	if err != nil {
		t.Fatalf("FromNetMap: %v", err)
	}
	cfg := BuildWGConfig(nm)
	m := &relayMeter{}
	m.SetRelayRate(relayRateBytesPerSec(cfg.RelayBandwidthKbps), relayRateBytesPerSec(cfg.RelayBandwidthBurstKbps))
	m.charge(64 << 20)
	start := time.Now()
	m.settle(context.Background())
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Fatalf("no allowance in the netmap must mean no throttling; waited %v", d)
	}
}
