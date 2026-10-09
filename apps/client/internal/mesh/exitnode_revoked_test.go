package mesh

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/calabinet/calabi/apps/client/internal/hostnet"
	meshpb "github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
)

// lockedBuffer is a log sink the test can read while the session's goroutines
// are still writing to it.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) lines() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Split(strings.TrimSpace(l.b.String()), "\n")
}

// Revoking an exit device's approval takes its default route out of the netmap
// and leaves the device itself in it. A node that had chosen it as its exit must
// go back to its own connection. Before this it kept the full-tunnel routes: the
// selection still resolved, by name, to a peer that was there, so nothing told
// the datapath to remove them — while WireGuard, handed a peer with no default
// route, had nobody to give an internet-bound packet to. Everything the routes
// sent into the tun was dropped there, and the machine was offline until someone
// cleared the selection on it by hand.
//
// Walks the path a real netmap takes (coordinator stream -> BuildWGConfig ->
// exit selection -> datapath -> wireguard-go), because the two halves that have
// to agree — the OS routes and WireGuard's allowed-ips — are only both real at
// the far end of it.
func TestRevokedExitDeviceFallsBackToDirect(t *testing.T) {
	hostnet.SetInterfaceLister(func() ([]hostnet.Interface, error) { return nil, nil })
	t.Cleanup(func() { hostnet.SetInterfaceLister(nil) })

	netmap := func(exitRoutes ...string) *meshpb.NetMap {
		return &meshpb.NetMap{
			Self: &meshpb.Peer{NodeId: 1, NodeKey: keyB64(1), OverlayAddr: "100.64.0.1"},
			Peers: []*meshpb.Peer{
				{NodeId: 2, NodeKey: keyB64(2), Name: "office-exit", OverlayAddr: "100.64.0.2",
					AllowedIps: append([]string{"100.64.0.2/32"}, exitRoutes...)},
				{NodeId: 3, NodeKey: keyB64(3), Name: "laptop", OverlayAddr: "100.64.0.3",
					AllowedIps: []string{"100.64.0.3/32"}},
			},
		}
	}
	steps := []struct {
		name     string
		routes   []string
		wantExit bool
	}{
		{"approved", []string{"0.0.0.0/0", "::/0"}, true},
		{"approval revoked", nil, false},
		// The coordinator re-sends an unchanged netmap several times a minute.
		{"the same netmap again", nil, false},
		// The full tunnel captures IPv4 only, so an exit that may carry IPv6 alone
		// cannot take any of what the routes would send it.
		{"only the IPv6 default route approved", []string{"::/0"}, false},
		{"only the IPv4 default route approved", []string{"0.0.0.0/0"}, true},
	}
	f := &fakeCoord{reg: &meshpb.RegisterNodeResponse{NodeId: 1, OverlayAddr: "100.64.0.1"}}
	for _, s := range steps {
		f.netmaps = append(f.netmaps, netmap(s.routes...))
	}

	logs := &lockedBuffer{}
	logger := slog.New(slog.NewTextHandler(logs, nil))
	dp := &recordingDatapath{ch: make(chan WGConfig, len(steps))}
	ctrl := &Controller{
		Coord:    dialFake(t, f),
		Datapath: dp,
		Params:   RegisterParams{AuthKey: "k", NodeKey: testKey(1).Public(), NodePrivate: testKey(1), Name: "phone"},
		ExitNode: "office-exit",
		Logger:   logger,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ctrl.Run(ctx) }()

	// A desktop's routing: its own sockets do not bypass the tunnel, so direct
	// paths pause for as long as the full tunnel is up.
	rt := &recordingRouting{}
	const relay = "127.0.0.1:1" // nothing listens: the relay stays down, which the datapath tolerates
	d, err := NewWGDatapathOnTUN(tuntest.NewChannelTUN().TUN(), rt, testKey(1), relay, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	for _, s := range steps {
		var cfg WGConfig
		select {
		case cfg = <-dp.ch:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: datapath never received a config from the netmap", s.name)
		}
		cfg.SelfRelay = relay
		if err := d.SetConfig(cfg); err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}

		// The OS half: are the full-tunnel routes in place right now?
		rt.mu.Lock()
		routed := rt.exits-rt.cleanups == 1
		rt.mu.Unlock()
		// The WireGuard half: does any peer take a packet for the internet?
		dump, err := d.dev.IpcGet()
		if err != nil {
			t.Fatal(err)
		}
		claimed := false
		for _, p := range parseUAPI(dump) {
			for _, aip := range p.AllowedIPs {
				if aip == "0.0.0.0/0" {
					claimed = true
				}
			}
		}
		if routed && !claimed {
			t.Errorf("%s: the full-tunnel routes are installed and no WireGuard peer carries 0.0.0.0/0 — every internet-bound packet enters the tun and is dropped there", s.name)
		}
		if routed != s.wantExit || claimed != s.wantExit {
			t.Errorf("%s: full-tunnel routes installed = %v, a peer carries 0.0.0.0/0 = %v; want both %v",
				s.name, routed, claimed, s.wantExit)
		}
		if got := !cfg.ExitNode.IsZero(); got != s.wantExit {
			t.Errorf("%s: config names an exit device = %v, want %v", s.name, got, s.wantExit)
		}
		d.bind.dmu.Lock()
		directOff := d.bind.directOff
		d.bind.dmu.Unlock()
		if directOff != s.wantExit {
			t.Errorf("%s: direct paths paused = %v, want %v (they pause only under a full tunnel)", s.name, directOff, s.wantExit)
		}
	}

	// Said once per change, not once per netmap: when the approval goes, and
	// again when what is offered changes to something that still cannot be used.
	var said []string
	for _, line := range logs.lines() {
		if strings.Contains(line, "level=WARN") && strings.Contains(line, "exit_node=office-exit") {
			said = append(said, line)
		}
	}
	if len(said) != 2 {
		t.Fatalf("WARN lines about the chosen exit device = %d, want 2 (approval gone; then IPv6 only):\n%s",
			len(said), strings.Join(said, "\n"))
	}
	for i, want := range []string{"default_routes_offered=none", "default_routes_offered=::/0"} {
		if !strings.Contains(said[i], "not offering the IPv4 default route") || !strings.Contains(said[i], want) {
			t.Errorf("WARN %d = %s\nwant it to say the exit device is not offering the IPv4 default route, with %s", i+1, said[i], want)
		}
	}
}
