package mesh

import (
	"context"
	"log/slog"
	"testing"
	"time"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
	meshpb "github.com/calabi/calabi/pkg/mesh-proto/meshpb"
)

// The real datapath must satisfy the resume hook. This is the assertion that
// matters most in this file: resumeFromSleep is unexported, so a rename or a
// receiver typo would not break any build — the type would just quietly stop
// matching sleepResumer and the wake path would do nothing, forever, silently.
var _ sleepResumer = (*WGDatapath)(nil)

// A link that stops answering is torn down and re-dialed. This is the
// resume-from-standby case: the socket still accepts writes (the fake relay is
// alive and reading), it simply never says anything back.
func TestRelayPoolReapsLinkThatStopsAnswering(t *testing.T) {
	relay := startFakeRelay(t) // accepts, never answers a keepalive
	p := newRelayPoolTimed(meshproto.NodeKey{1}, [meshproto.KeyLen]byte{}, nil, slog.Default(),
		20*time.Millisecond, 60*time.Millisecond)
	defer p.Close()
	if err := p.DialHome(context.Background(), relay.addr); err != nil {
		t.Fatalf("dial home: %v", err)
	}

	// A second connection to the same relay means the first was reaped and the
	// home link re-dialed — the pool noticed on its own, with no send in flight.
	deadline := time.Now().Add(3 * time.Second)
	for relay.links() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("silent link was never reaped (links=%d)", relay.links())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The other half: a relay that answers keeps its link. Without this, the test
// above would also pass on an implementation that just reconnects on a timer.
func TestRelayPoolKeepsLinkThatAnswers(t *testing.T) {
	relay := startLiveFakeRelay(t)
	p := newRelayPoolTimed(meshproto.NodeKey{1}, [meshproto.KeyLen]byte{}, nil, slog.Default(),
		20*time.Millisecond, 60*time.Millisecond)
	defer p.Close()
	if err := p.DialHome(context.Background(), relay.addr); err != nil {
		t.Fatalf("dial home: %v", err)
	}

	time.Sleep(300 * time.Millisecond) // ~15 sweeps, ~5 idle deadlines
	if got := relay.links(); got != 1 {
		t.Fatalf("healthy link was re-dialed %d times; the sweep is churning", got-1)
	}
	if addrs := p.Addrs(); len(addrs) != 1 || addrs[0] != relay.addr {
		t.Fatalf("pool lost the healthy link: %v", addrs)
	}
}

// ResetLinks drops everything and comes straight back on the home relay, rather
// than waiting for the sweep to prove each link dead one at a time.
func TestRelayPoolResetLinksRedialsHome(t *testing.T) {
	relay := startLiveFakeRelay(t)
	p := newRelayPoolTimed(meshproto.NodeKey{1}, [meshproto.KeyLen]byte{}, nil, slog.Default(),
		time.Hour, time.Hour) // sweep disabled: only ResetLinks can act here
	defer p.Close()
	if err := p.DialHome(context.Background(), relay.addr); err != nil {
		t.Fatalf("dial home: %v", err)
	}

	p.ResetLinks()

	deadline := time.Now().Add(3 * time.Second)
	for relay.links() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("ResetLinks did not re-dial the home relay")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for {
		if addrs := p.Addrs(); len(addrs) == 1 && addrs[0] == relay.addr {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("home link never came back: %v", p.Addrs())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// resumeRecorder is a Datapath that records having been told the machine woke.
type resumeRecorder struct {
	recordingDatapath
	resumed chan struct{}
}

func (d *resumeRecorder) resumeFromSleep() {
	select {
	case d.resumed <- struct{}{}:
	default:
	}
}

// onWake reaches the datapath. The relay links are the part of a resumed session
// that fails silently, so they are the part that must be rebuilt without waiting
// for something else to notice.
func TestControllerOnWakeResetsTheDatapath(t *testing.T) {
	dp := &resumeRecorder{
		recordingDatapath: recordingDatapath{ch: make(chan WGConfig, 1)},
		resumed:           make(chan struct{}, 1),
	}
	c := &Controller{Datapath: dp, Logger: slog.Default()}
	c.onWake(context.Background(), 1, nil, nil) // no socket, no prober: relay path only
	select {
	case <-dp.resumed:
	default:
		t.Fatal("onWake did not tell the datapath to rebuild its transport")
	}
}

func TestWokeUp(t *testing.T) {
	tests := []struct {
		name       string
		mono, wall time.Duration
		want       bool
	}{
		{"an ordinary tick", wakeCheckInterval, wakeCheckInterval, false},
		{"a busy machine, not a sleeping one", 20 * time.Second, 20 * time.Second, false},
		{"monotonic stopped across the suspend", wakeCheckInterval, 20 * time.Minute, true},
		{"monotonic kept running through it", 20 * time.Minute, wakeCheckInterval, true},
		{"both saw it", time.Hour, time.Hour, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := wokeUp(tt.mono, tt.wall); got != tt.want {
				t.Fatalf("wokeUp(%s, %s) = %v, want %v", tt.mono, tt.wall, got, tt.want)
			}
		})
	}
}

// A session's loops must not outlive the session.
//
// The regression: they were bound to the CALLER's context, which is the daemon's
// and survives every reconnect. Each ended session therefore left its endpoint
// reporter, home prober, service-health loop and DISCO prober running against a
// coord connection that was about to be closed — forever, and one more set per
// reconnect. What the user saw was several "report endpoints failed: the client
// connection is closing" a minute, at as many tick phases as there had been
// reconnects, until the daemon was restarted.
func TestControllerRunStopsItsLoopsWhenItReturns(t *testing.T) {
	const reportEvery = 20 * time.Millisecond

	f := &fakeCoord{
		reg:        &meshpb.RegisterNodeResponse{NodeId: 1, OverlayAddr: "100.64.0.1"},
		reportedCh: make(chan []string, 64),
		endWatch:   true, // the netmap stream ends, so Run returns
		netmaps: []*meshpb.NetMap{{
			Self: &meshpb.Peer{NodeId: 1, NodeKey: keyB64(1), OverlayAddr: "100.64.0.1"},
		}},
	}
	ctrl := &Controller{
		Coord:       dialFake(t, f),
		Datapath:    &recordingDatapath{ch: make(chan WGConfig, 4)},
		Params:      RegisterParams{AuthKey: "k", NodeKey: mustKey(1), Name: "laptop"},
		Logger:      slog.Default(),
		reportEvery: reportEvery,
	}

	// The caller's context stays LIVE for the whole test — that is the point. So
	// does the coord connection, so a leaked loop would keep reporting happily.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { _ = ctrl.Run(ctx); close(done) }()

	select {
	case <-f.reportedCh:
	case <-time.After(2 * time.Second):
		t.Skip("host reported no endpoints (loopback only?) — nothing to observe here")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run never returned after the netmap stream ended")
	}

	time.Sleep(100 * time.Millisecond) // let anything already in flight land
	before := f.reports()
	time.Sleep(20 * reportEvery)
	if after := f.reports(); after != before {
		t.Fatalf("the endpoint reporter outlived its session: %d more reports after Run returned", after-before)
	}
}
