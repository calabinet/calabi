package mesh

import (
	"context"
	"log/slog"
	"testing"
	"time"

	meshpb "github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
)

func TestControllerRelayOnlyStillAppliesAuthoritativeMembers(t *testing.T) {
	f := &fakeCoord{reg: &meshpb.RegisterNodeResponse{NodeId: 1, OverlayAddr: "100.64.0.1"},
		reportedCh: make(chan []string, 4), netmaps: []*meshpb.NetMap{{
			Self:  &meshpb.Peer{NodeId: 1, NodeKey: keyB64(1), OverlayAddr: "100.64.0.1"},
			Peers: []*meshpb.Peer{{NodeId: 2, NodeKey: keyB64(2), OverlayAddr: "100.64.0.2"}},
		}}}
	dp := &recordingDatapath{ch: make(chan WGConfig, 4)}
	ctrl := &Controller{RelayOnly: true, Coord: dialFake(t, f), Datapath: dp,
		Params: RegisterParams{AuthKey: "k", NodeKey: testKey(1).Public(), NodePrivate: testKey(1)}, Logger: slog.Default()}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = ctrl.Run(ctx) }()
	defer func() { cancel(); <-done }()
	select {
	case <-dp.ch:
	case <-time.After(2 * time.Second):
		t.Fatal("relay-only netmap was not applied")
	}
	// SetConfig precedes member publication in the callback. Wait for that
	// observable state, not an arbitrary sleep or UDP timing assumption.
	deadline := time.Now().Add(time.Second)
	for !ctrl.MembershipReady() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !ctrl.MembershipReady() || len(ctrl.FileMembers()) != 1 {
		t.Fatal("relay-only lost authoritative membership")
	}
	select {
	case <-f.reportedCh:
		t.Fatal("relay-only advertised a direct UDP endpoint")
	default:
	}
}
