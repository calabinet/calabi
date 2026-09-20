package mesh

import (
	"context"
	"log/slog"
	"testing"
	"time"

	meshpb "github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
)

// A desktop session must keep running at exactly the cadence it always had:
// Timing exists for phones, not to retune the fleet.
func TestDesktopTimingIsTheShippedCadence(t *testing.T) {
	// TunnelReport is new (2026-09); it runs only when the daemon has tunnels
	// to report to a self-hosted coordinator.
	want := Timing{
		DiscoProbe:          5 * time.Second,
		EndpointReport:      60 * time.Second,
		HomeProbe:           5 * time.Minute,
		ConnReport:          5 * time.Minute,
		ServiceHealth:       time.Minute,
		TunnelReport:        5 * time.Minute,
		WakeDetect:          true,
		PersistentKeepalive: 25 * time.Second,
	}
	if got := DesktopTiming(); got != want {
		t.Fatalf("DesktopTiming() = %+v, want %+v", got, want)
	}
	if got := (&Controller{}).timing(); got != want {
		t.Fatalf("a Controller with no Timing runs %+v, want the desktop cadence", got)
	}
}

// The keepalive each peer gets comes from the session's Timing: a phone turns it
// off, a desktop keeps 25s.
func TestSessionTimingSetsThePeerKeepalive(t *testing.T) {
	for _, tc := range []struct {
		name   string
		timing *Timing
		want   time.Duration
	}{
		{"desktop", nil, 25 * time.Second},
		{"phone", &Timing{}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeCoord{
				reg: &meshpb.RegisterNodeResponse{NodeId: 1, OverlayAddr: "100.64.0.1"},
				netmaps: []*meshpb.NetMap{{
					Self:  &meshpb.Peer{NodeId: 1, NodeKey: keyB64(1), OverlayAddr: "100.64.0.1"},
					Peers: []*meshpb.Peer{{NodeId: 2, NodeKey: keyB64(2), OverlayAddr: "100.64.0.2", AllowedIps: []string{"100.64.0.2/32"}}},
				}},
			}
			dp := &recordingDatapath{ch: make(chan WGConfig, 4)}
			ctrl := &Controller{
				Coord:    dialFake(t, f),
				Datapath: dp,
				Params:   RegisterParams{AuthKey: "k", NodeKey: testKey(1).Public(), NodePrivate: testKey(1), Name: "n"},
				Timing:   tc.timing,
				Logger:   slog.Default(),
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() { _ = ctrl.Run(ctx) }()
			select {
			case cfg := <-dp.ch:
				if len(cfg.Peers) != 1 || cfg.Peers[0].PersistentKeepalive != tc.want {
					t.Fatalf("peers = %+v, want one peer with keepalive %v", cfg.Peers, tc.want)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("datapath never received a config")
			}
		})
	}
}

// A zero interval turns a loop off: it returns at once instead of ticking (and
// instead of panicking in time.NewTicker, which refuses a zero duration).
func TestZeroIntervalLoopsReturnAtOnce(t *testing.T) {
	c := &Controller{Timing: &Timing{}, Logger: slog.Default(), Coord: &CoordClient{},
		Tunnels: NewTunnelMeter(func() []TunnelState { return nil })}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // only reached if a loop did NOT return on its own

	for name, loop := range map[string]func(){
		"endpoint report": func() { c.endpointReportLoop(ctx, 1, nil) },
		"home probe":      func() { c.homeProbeLoop(ctx, 1, nil) },
		"disco probe":     func() { (&discoProber{}).run(ctx, 0, c.peers) },
		"tunnel report":   func() { c.tunnelReportLoop(ctx) },
	} {
		done := make(chan struct{})
		go func() { defer close(done); loop() }()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Errorf("%s loop with a zero interval is still running", name)
		}
	}
}
