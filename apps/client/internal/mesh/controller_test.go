package mesh

import (
	"context"
	"log/slog"
	"testing"
	"time"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
	meshpb "github.com/calabi/calabi/pkg/mesh-proto/meshpb"
)

// recordingDatapath captures the configs the controller applies.
type recordingDatapath struct{ ch chan WGConfig }

func (d *recordingDatapath) SetConfig(cfg WGConfig) error { d.ch <- cfg; return nil }
func (d *recordingDatapath) Close() error                 { return nil }

// Run generates a per-session DISCO key and sends its public half on
// registration, then opens the direct-path socket and reports candidate
// endpoints (MESH.4 B1). The disco key on register is deterministic; the endpoint
// report depends on the host having a usable interface, so it's checked
// best-effort (this box has one, a locked-down env may not).
func TestControllerRegistersWithDiscoKeyAndReportsEndpoints(t *testing.T) {
	f := &fakeCoord{
		reg:        &meshpb.RegisterNodeResponse{NodeId: 1, OverlayAddr: "100.64.0.1"},
		reportedCh: make(chan []string, 4),
		netmaps: []*meshpb.NetMap{{
			Self: &meshpb.Peer{NodeId: 1, NodeKey: keyB64(1), OverlayAddr: "100.64.0.1"},
		}},
	}
	c := dialFake(t, f)
	dp := &recordingDatapath{ch: make(chan WGConfig, 4)}
	ctrl := &Controller{
		Coord:    c,
		Datapath: dp,
		Params:   RegisterParams{AuthKey: "k", NodeKey: mustKey(1), Name: "laptop"},
		Logger:   slog.Default(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ctrl.Run(ctx) }()

	// A datapath config arrives only after register + the first netmap, so this
	// also guarantees register happened before we inspect it.
	select {
	case <-dp.ch:
	case <-time.After(2 * time.Second):
		t.Fatal("no netmap applied (register never completed)")
	}
	f.mu.Lock()
	reg := f.lastReg
	f.mu.Unlock()
	if reg == nil || reg.GetDiscoKey() == "" {
		t.Fatalf("register did not carry a disco key: %+v", reg)
	}
	if _, err := meshproto.ParseDiscoKey(reg.GetDiscoKey()); err != nil {
		t.Fatalf("register disco_key not a valid key: %v", err)
	}

	// Best-effort: on a host with a usable interface, endpoints are reported.
	select {
	case eps := <-f.reportedCh:
		if len(eps) == 0 {
			t.Fatalf("reported an empty endpoint set")
		}
	case <-time.After(1 * time.Second):
		t.Log("no endpoints reported (host may have only loopback) — best-effort, not failing")
	}
}

func TestControllerAppliesNetMapToDatapath(t *testing.T) {
	f := &fakeCoord{
		reg: &meshpb.RegisterNodeResponse{NodeId: 1, OverlayAddr: "100.64.0.1"},
		netmaps: []*meshpb.NetMap{{
			Self:  &meshpb.Peer{NodeId: 1, NodeKey: keyB64(1), OverlayAddr: "100.64.0.1"},
			Peers: []*meshpb.Peer{{NodeId: 2, NodeKey: keyB64(2), OverlayAddr: "100.64.0.2", AllowedIps: []string{"100.64.0.2/32"}}},
		}},
	}
	c := dialFake(t, f)
	dp := &recordingDatapath{ch: make(chan WGConfig, 4)}
	ctrl := &Controller{
		Coord:    c,
		Datapath: dp,
		Params:   RegisterParams{AuthKey: "k", NodeKey: mustKey(1), Name: "laptop"},
		Logger:   slog.Default(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ctrl.Run(ctx) }()

	select {
	case cfg := <-dp.ch:
		if cfg.OverlayAddr.String() != "100.64.0.1" {
			t.Fatalf("overlay = %s", cfg.OverlayAddr)
		}
		if len(cfg.Peers) != 1 || cfg.Peers[0].PublicKey != mustKey(2) {
			t.Fatalf("peers = %+v", cfg.Peers)
		}
		if len(cfg.Peers[0].AllowedIPs) != 1 || cfg.Peers[0].AllowedIPs[0].String() != "100.64.0.2/32" {
			t.Fatalf("allowed_ips = %v", cfg.Peers[0].AllowedIPs)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("datapath never received a config from the netmap")
	}
}
