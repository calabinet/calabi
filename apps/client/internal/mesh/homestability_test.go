package mesh

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"github.com/calabinet/calabi/pkg/mesh-proto/stun"
)

// startScriptedSTUN runs a loopback STUN server whose behaviour a test controls:
// answer decides, per request, whether to reply (false = the datagram is "lost").
func startScriptedSTUN(t *testing.T, answer func(n int) bool) netip.AddrPort {
	t.Helper()
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	go func() {
		buf := make([]byte, 1500)
		n := 0
		for {
			sz, from, err := srv.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			tx, ok := stun.IsBindingRequest(buf[:sz])
			if !ok {
				continue
			}
			n++
			if !answer(n) {
				continue
			}
			_, _ = srv.WriteToUDPAddrPort(stun.BindingResponse(tx, netip.AddrPortFrom(from.Addr().Unmap(), from.Port())), from)
		}
	}()
	ap := srv.LocalAddr().(*net.UDPAddr).AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

func testSock(t *testing.T) *magicSock {
	t.Helper()
	disco, _ := GenerateDiscoKey()
	ms, err := newMagicSock(disco, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ms.Close() })
	return ms
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// THE FLAP, as it happened: a node 190ms from one platform relay and 240ms from
// another kept re-homing between them. One lost probe datagram makes the probe
// retransmit 300ms later, so a single sample reads the nearer relay as ~490ms —
// slower than the farther one by twenty times the switch margin.
//
// Here the near relay drops the first datagram it ever sees and is otherwise
// instant; the far one is a steady 120ms. Measured once, near loses. Measured as
// the best of a few, it is what it is: near.
func TestProbeRegionsIsNotFooledByOneLostDatagram(t *testing.T) {
	near := startScriptedSTUN(t, func(n int) bool { return n > 1 })
	far := startSTUNResponder(t, 120*time.Millisecond)
	ms := testSock(t)

	m := DERPMap{Regions: []DERPRegion{regionAt("far", far), regionAt("near", near)}}
	got := probeRegions(context.Background(), ms, m, quietLogger())
	if len(got) != 2 {
		t.Fatalf("measured %+v, want both regions", got)
	}
	if got[0].Region != "near" {
		t.Fatalf("fastest = %s (%v) ahead of %s (%v); one lost datagram was read as latency",
			got[0].Region, got[0].RTT, got[1].Region, got[1].RTT)
	}
	if got[0].RTT > 100*time.Millisecond {
		t.Fatalf("near measured %v: the retransmit delay leaked into its figure", got[0].RTT)
	}
}

func TestBestOf(t *testing.T) {
	seq := func(vals ...time.Duration) (func() (time.Duration, bool), *int) {
		i := 0
		return func() (time.Duration, bool) {
			v := vals[i]
			i++
			return v, v >= 0
		}, &i
	}
	const lost = -1 // a sample that got no answer

	// Loss only ever adds time, so the smallest sample is the path.
	s, _ := seq(490*time.Millisecond, 190*time.Millisecond, 193*time.Millisecond)
	if got, ok := bestOf(3, s); !ok || got != 190*time.Millisecond {
		t.Fatalf("bestOf = %v ok=%v, want 190ms", got, ok)
	}
	// A dead region costs ONE timeout, not n: the first silence ends it.
	s, calls := seq(lost, 10*time.Millisecond, 10*time.Millisecond)
	if _, ok := bestOf(3, s); ok || *calls != 1 {
		t.Fatalf("a silent first sample: ok=%v after %d samples, want unreachable after 1", ok, *calls)
	}
	// Follow-ups that fail are not counted, and do not undo the first.
	s, _ = seq(200*time.Millisecond, lost, lost)
	if got, ok := bestOf(3, s); !ok || got != 200*time.Millisecond {
		t.Fatalf("bestOf = %v ok=%v, want the first sample's 200ms", got, ok)
	}
}

func TestHomeWorthConfirming(t *testing.T) {
	m := func(regions ...string) []regionRTT {
		out := make([]regionRTT, 0, len(regions))
		for i, r := range regions {
			out = append(out, regionRTT{Region: r, RTT: time.Duration(i+1) * time.Millisecond})
		}
		return out
	}
	cases := []struct {
		name     string
		current  string
		measured []regionRTT
		pref     homePref
		pinned   string
		want     bool
	}{
		{"a silent home is asked again before it is replaced", "lax", m("sgp"), homeAnyRelay, "", true},
		{"nothing answered at all: still ask the home", "lax", nil, homeAnyRelay, "", true},
		{"a home that answered needs no confirming", "lax", m("lax", "sgp"), homeAnyRelay, "", false},
		{"no home yet", "", m("sgp"), homeAnyRelay, "", false},
		// The user just switched to their own node. The old platform home is not a
		// candidate any more, so waiting on it would only delay the switch.
		{"the preference moved to a class that answered", "lax", m("self-office"), homePreferOwn, "", false},
		{"switched to platform, and a platform relay answered", "self-office", m("sgp"), homePreferPlatform, "", false},
		// ...but a preference whose class has nothing reachable falls back to every
		// relay, and then the silent home IS a candidate again.
		{"preferred class unreachable: the home still counts", "lax", m("sgp"), homePreferOwn, "", true},
		{"a silent home of the preferred class", "self-office", m("lax"), homePreferOwn, "", true},
		// A pinned region that answered wins outright; the old home is irrelevant.
		{"the pin answered", "lax", m("self-office"), homePreferOwn, "self-office", false},
		{"the pin is the silent home", "self-office", m("lax"), homePreferOwn, "self-office", true},
		{"the pin did not answer either", "lax", m("sgp"), homeAnyRelay, "self-office", true},
	}
	for _, tc := range cases {
		if got := homeWorthConfirming(tc.current, tc.measured, tc.pref, tc.pinned); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A home that stays silent for one whole round but answers when asked again is
// not replaced. The other relay is the only one that answered the round, so
// without the confirmation the node moves to it — a slower relay, picked because
// a burst of loss happened to land on the probe.
func TestHomeProbeKeepsAHomeThatMissesOneRound(t *testing.T) {
	// Silent for the first round (longer than one probe timeout), then instant.
	var first atomic.Int64
	home := startScriptedSTUN(t, func(int) bool {
		now := time.Now().UnixNano()
		first.CompareAndSwap(0, now)
		return time.Duration(now-first.Load()) > stunProbeTimeout+200*time.Millisecond
	})
	other := startSTUNResponder(t, 100*time.Millisecond)
	ms := testSock(t)

	f := &fakeCoord{reg: &meshpb.RegisterNodeResponse{NodeId: 7}}
	c := &Controller{Logger: quietLogger(), Coord: dialFake(t, f), homeMissRetry: 300 * time.Millisecond}
	c.setDERPMap(DERPMap{Regions: []DERPRegion{regionAt("home", home), regionAt("other", other)}}, "home")

	c.homeProbe(context.Background(), 7, ms)

	if got := c.getHome(); got != "home" {
		t.Fatalf("home = %q after one silent round, want it kept", got)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, h := range f.reportedHome {
		if h != "home" {
			t.Fatalf("reported homes %v: the node moved off a home that was only briefly silent", f.reportedHome)
		}
	}
}

// The other half: a home that is really gone is still left — after the one
// confirmation, not five minutes later at the next round.
func TestHomeProbeLeavesAHomeThatStaysSilent(t *testing.T) {
	dead := startScriptedSTUN(t, func(int) bool { return false })
	other := startSTUNResponder(t, 0)
	ms := testSock(t)

	f := &fakeCoord{reg: &meshpb.RegisterNodeResponse{NodeId: 7}}
	c := &Controller{Logger: quietLogger(), Coord: dialFake(t, f), homeMissRetry: 50 * time.Millisecond}
	c.setDERPMap(DERPMap{Regions: []DERPRegion{regionAt("home", dead), regionAt("other", other)}}, "home")

	c.homeProbe(context.Background(), 7, ms)

	if got := c.getHome(); got != "other" {
		t.Fatalf("home = %q, want the node to have left the silent one for %q", got, "other")
	}
}

// Flipping "which node I use" re-selects the home on the session that is
// ALREADY RUNNING. It used to take a whole new session to change this bias;
// here there is one session, one Controller, and the home still moves.
func TestSetHomeSelectionRehomesTheRunningSession(t *testing.T) {
	platform := startSTUNResponder(t, 0)
	own := startSTUNResponder(t, 60*time.Millisecond) // slower: only a preference picks it
	ms := testSock(t)

	f := &fakeCoord{reg: &meshpb.RegisterNodeResponse{NodeId: 7}}
	off := Timing{} // no periodic probe: the only thing that can move the home is the kick
	c := &Controller{Logger: quietLogger(), Coord: dialFake(t, f), HomePreference: "platform", Timing: &off}
	c.setDERPMap(DERPMap{Regions: []DERPRegion{regionAt("us-west", platform), regionAt("self-office", own)}}, "us-west")

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); c.homeProbeLoop(ctx, 7, ms) }()
	defer func() { cancel(); wg.Wait() }()

	c.homeProbe(ctx, 7, ms)
	if got := c.getHome(); got != "us-west" {
		t.Fatalf("home = %q with the platform preferred, want us-west", got)
	}

	if !c.SetHomeSelection("own", "") {
		t.Fatal("SetHomeSelection reported no change for a flipped preference")
	}
	if c.SetHomeSelection("own", "") {
		t.Fatal("SetHomeSelection reported a change for the same selection")
	}
	deadline := time.Now().Add(5 * time.Second)
	for c.getHome() != "self-office" {
		if time.Now().After(deadline) {
			t.Fatalf("home = %q five seconds after the preference flipped, want self-office", c.getHome())
		}
		time.Sleep(20 * time.Millisecond)
	}
	// And the coordinator hears about it, which is what moves the relay link and
	// tells every peer where to send.
	for {
		f.mu.Lock()
		n := len(f.reportedHome)
		last := ""
		if n > 0 {
			last = f.reportedHome[n-1]
		}
		f.mu.Unlock()
		if last == "self-office" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the coordinator was told %q, want the new home reported", last)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// The pin, too: the edge landed in a facility, and the relay there is named.
	if !c.SetHomeSelection("own", "self-office") {
		t.Fatal("adding a pin is a change")
	}
	if pref, pin := c.homeSelection(); pref != homePreferOwn || pin != "self-office" {
		t.Fatalf("selection = %v/%q after pinning", pref, pin)
	}
}
