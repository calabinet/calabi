package mesh

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/calabinet/calabi/apps/client/internal/hostnet"
	meshpb "github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
)

// Choosing an exit device must put its default route into WireGuard, following
// the path a real netmap takes: coordinator stream -> BuildWGConfig -> route
// policy -> datapath. The datapath tests hand SetConfig a WGConfig they built
// themselves, so none of them went through BuildWGConfig — where the MESH-1
// guard dropped 0.0.0.0/0 for overlapping the node pool. From 2026-09-10 every
// exit device looked selected on every client and forwarded nothing. Found on a
// real phone: routes and "exit node engaged" in place, zero bytes to the exit.
func TestChosenExitDeviceGetsTheDefaultRouteInWireGuard(t *testing.T) {
	hostnet.SetInterfaceLister(func() ([]hostnet.Interface, error) { return nil, nil })
	t.Cleanup(func() { hostnet.SetInterfaceLister(nil) })

	f := &fakeCoord{
		reg: &meshpb.RegisterNodeResponse{NodeId: 1, OverlayAddr: "100.64.0.1"},
		netmaps: []*meshpb.NetMap{{
			Self: &meshpb.Peer{NodeId: 1, NodeKey: keyB64(1), OverlayAddr: "100.64.0.1"},
			Peers: []*meshpb.Peer{
				{NodeId: 2, NodeKey: keyB64(2), Name: "office-exit", OverlayAddr: "100.64.0.2",
					AllowedIps: []string{"100.64.0.2/32", "0.0.0.0/0", "::/0"}},
				// Still refused: a prefix that overlaps the node pool without being
				// the default route is the MESH-1 shape.
				{NodeId: 3, NodeKey: keyB64(3), Name: "mallory", OverlayAddr: "100.64.0.3",
					AllowedIps: []string{"100.64.0.3/32", "100.64.0.0/10"}},
			},
		}},
	}
	dp := &recordingDatapath{ch: make(chan WGConfig, 4)}
	ctrl := &Controller{
		Coord:    dialFake(t, f),
		Datapath: dp,
		Params:   RegisterParams{AuthKey: "k", NodeKey: testKey(1).Public(), NodePrivate: testKey(1), Name: "phone"},
		ExitNode: "office-exit",
		// Declining other devices' subnets must not decline the exit this node chose.
		Routes: RoutePolicy{Accept: false},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ctrl.Run(ctx) }()

	var cfg WGConfig
	select {
	case cfg = <-dp.ch:
	case <-time.After(2 * time.Second):
		t.Fatal("datapath never received a config from the netmap")
	}
	if cfg.ExitNode != mustKey(2) {
		t.Fatalf("exit node = %v, want office-exit", cfg.ExitNode)
	}

	rt := &recordingRouting{}
	d, err := NewWGDatapathOnTUN(tuntest.NewChannelTUN().TUN(), rt, testKey(1), "127.0.0.1:1", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	cfg.SelfRelay = "127.0.0.1:1"
	if err := d.SetConfig(cfg); err != nil {
		t.Fatal(err)
	}
	dump, err := d.dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, p := range parseUAPI(dump) {
		got[p.PublicKey] = p.AllowedIPs
	}
	exit := strings.Join(got[mustKey(2).String()], " ")
	for _, want := range []string{"100.64.0.2/32", "0.0.0.0/0", "::/0"} {
		if !strings.Contains(exit, want) {
			t.Errorf("exit device's allowed-ips in WireGuard = [%s], missing %s", exit, want)
		}
	}
	if m := strings.Join(got[mustKey(3).String()], " "); m != "100.64.0.3/32" {
		t.Errorf("mallory's allowed-ips in WireGuard = [%s], want only its own address", m)
	}
}
