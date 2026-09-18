package mesh

import (
	"context"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/calabi/calabi/apps/client/internal/hostnet"
	meshpb "github.com/calabi/calabi/pkg/mesh-proto/meshpb"
)

// A phone's platform reports a network change (Wi-Fi to cellular, a new network)
// and the running session must repair right away — rebuild the relay links and
// re-advertise its endpoints — instead of waiting for a timer that, on a phone,
// may be minutes away.
func TestNetworkChangedRepairsTheRunningSession(t *testing.T) {
	// One usable address, so every endpoint report has something to carry and
	// the count below does not depend on this machine's interfaces.
	hostnet.SetInterfaceLister(func() ([]hostnet.Interface, error) {
		return []hostnet.Interface{{Name: "wlan0", Up: true, Addrs: []hostnet.Address{
			{Addr: netip.MustParseAddr("192.0.2.7"), Bits: 24},
		}}}, nil
	})
	t.Cleanup(func() { hostnet.SetInterfaceLister(nil) })

	f := &fakeCoord{
		reg: &meshpb.RegisterNodeResponse{NodeId: 1, OverlayAddr: "100.64.0.1"},
		netmaps: []*meshpb.NetMap{{
			Self: &meshpb.Peer{NodeId: 1, NodeKey: keyB64(1), OverlayAddr: "100.64.0.1"},
		}},
	}
	dp := &resumeRecorder{
		recordingDatapath: recordingDatapath{ch: make(chan WGConfig, 4)},
		resumed:           make(chan struct{}, 1),
	}
	ctrl := &Controller{
		Coord:    dialFake(t, f),
		Datapath: dp,
		Params:   RegisterParams{AuthKey: "k", NodeKey: testKey(1).Public(), NodePrivate: testKey(1), Name: "phone"},
		Logger:   slog.Default(),
	}
	// A change reported before the session exists is not acted on later: the
	// session's own setup already reflects the network it starts on.
	ctrl.NetworkChanged()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ctrl.Run(ctx) }()

	select {
	case <-dp.ch:
	case <-time.After(2 * time.Second):
		t.Fatal("no netmap applied (the session never started)")
	}
	select {
	case <-dp.resumed:
		t.Fatal("a change signalled before the session started was acted on inside it")
	case <-time.After(200 * time.Millisecond):
	}
	before := f.reports()

	ctrl.NetworkChanged()
	select {
	case <-dp.resumed:
	case <-time.After(2 * time.Second):
		t.Fatal("NetworkChanged did not rebuild the datapath's relay links")
	}
	deadline := time.Now().Add(2 * time.Second)
	for f.reports() <= before {
		if time.Now().After(deadline) {
			t.Fatalf("NetworkChanged did not re-report endpoints (reports stayed at %d)", before)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
