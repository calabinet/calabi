package mesh

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

// listenOn starts a TCP listener on host and returns its port.
func listenOn(t *testing.T, host string) int {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Skipf("cannot listen on %s: %v", host, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func reportFor(reps []ServiceHealthReport, name string) ServiceHealthReport {
	for _, r := range reps {
		if r.Name == name {
			return r
		}
	}
	return ServiceHealthReport{}
}

// THE case this whole slice exists for. The app answers where the machine dials
// it and NOT on the address peers use — which is exactly what "bound to
// 127.0.0.1" looks like from outside, and is indistinguishable from "the app is
// down" unless the node checks both.
func TestLoopbackOnlyServiceIsDistinguishable(t *testing.T) {
	port := listenOn(t, "127.0.0.1")

	// A second loopback address stands in for the overlay: reachable on this
	// machine, but not the address the listener bound to.
	c := &Controller{Params: RegisterParams{Services: []DeclaredService{
		{Name: "db", Proto: "tcp", Port: port},
	}}}
	c.setOverlay(netip.MustParseAddr("127.0.0.2"))

	got := reportFor(c.checkServices(context.Background()), "db")
	if !got.Checked {
		t.Fatal("a tcp service was not checked")
	}
	if !got.TargetOK {
		t.Error("target probe failed against a listening socket")
	}
	if got.MeshOK {
		t.Error("the overlay probe succeeded against an address the app never bound")
	}
}

// Both green when the app listens on everything.
func TestServiceReachableOnBothAddresses(t *testing.T) {
	port := listenOn(t, "0.0.0.0")
	c := &Controller{Params: RegisterParams{Services: []DeclaredService{
		{Name: "web", Proto: "tcp", Port: port},
	}}}
	c.setOverlay(netip.MustParseAddr("127.0.0.1"))

	got := reportFor(c.checkServices(context.Background()), "web")
	if !got.Checked || !got.TargetOK || !got.MeshOK {
		t.Fatalf("a service listening on 0.0.0.0 reported %+v", got)
	}
}

// Nothing listening is neither of the interesting cases — it just isn't running.
func TestDeadServiceFailsBoth(t *testing.T) {
	// Bind and immediately release, so the port is almost certainly free.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	c := &Controller{Params: RegisterParams{Services: []DeclaredService{
		{Name: "gone", Proto: "tcp", Port: port},
	}}}
	c.setOverlay(netip.MustParseAddr("127.0.0.1"))

	got := reportFor(c.checkServices(context.Background()), "gone")
	if !got.Checked {
		t.Fatal("a tcp service was not checked")
	}
	if got.TargetOK || got.MeshOK {
		t.Errorf("a port nothing listens on reported %+v", got)
	}
}

// A udp dial is connectionless and succeeds against a port nothing is listening
// on, so its result would be worse than no result. Same for a node with no
// overlay address yet: absence of a check must not read as a failure.
func TestUncheckableServicesAreReportedAsUnchecked(t *testing.T) {
	c := &Controller{Params: RegisterParams{Services: []DeclaredService{
		{Name: "dns", Proto: "udp", Port: 53},
	}}}
	c.setOverlay(netip.MustParseAddr("127.0.0.1"))
	if got := reportFor(c.checkServices(context.Background()), "dns"); got.Checked {
		t.Error("a udp service was reported as checked")
	}

	noOverlay := &Controller{Params: RegisterParams{Services: []DeclaredService{
		{Name: "db", Proto: "tcp", Port: 5432},
	}}}
	if got := reportFor(noOverlay.checkServices(context.Background()), "db"); got.Checked {
		t.Error("a service was checked before the node had an overlay address")
	}
}

// An explicit target is what gets dialed; empty means loopback on the service's
// own port — the value a published tunnel also forwards to.
func TestTargetAddrResolution(t *testing.T) {
	if got := serviceTargetAddr(DeclaredService{Port: 5432}); got != "127.0.0.1:5432" {
		t.Errorf("default target = %q", got)
	}
	want := net.JoinHostPort("192.168.1.50", strconv.Itoa(6000))
	if got := serviceTargetAddr(DeclaredService{Port: 5432, Target: want}); got != want {
		t.Errorf("explicit target = %q, want %q", got, want)
	}
}

// THE regression for the console-authored case. Such a service exists only in
// the coordinator's registry — the machine's own config has never heard of it —
// so before the netmap carried it, it could never produce an observation at all.
// It is also the kind most likely to be pointed at the wrong address: nobody was
// standing at the machine when it was typed in.
func TestConsoleAuthoredServiceIsChecked(t *testing.T) {
	port := listenOn(t, "127.0.0.1")

	c := &Controller{} // nothing declared locally
	c.setOverlay(netip.MustParseAddr("127.0.0.2"))
	c.setSelfServices([]DeclaredService{{Name: "db", Proto: "tcp", Port: port}})

	got := reportFor(c.checkServices(context.Background()), "db")
	if !got.Checked {
		t.Fatal("a service registered only in the console was never checked")
	}
	if !got.TargetOK {
		t.Error("target probe failed against a listening socket")
	}
	if got.MeshOK {
		t.Error("the overlay probe succeeded against an address the app never bound")
	}
}

// The registry echoes back what the machine declared, so a name arriving from
// both sides must produce ONE entry — two rows for one name would report the
// same service twice and let the second overwrite the first.
func TestRegistryDoesNotDuplicateALocalDeclaration(t *testing.T) {
	c := &Controller{Params: RegisterParams{Services: []DeclaredService{
		{Name: "db", Proto: "tcp", Port: 5432, Target: "127.0.0.1:5432"},
	}}}
	c.setSelfServices([]DeclaredService{
		{Name: "db", Proto: "tcp", Port: 5432, Target: "10.0.0.9:5432"},
		{Name: "web", Proto: "tcp", Port: 8080},
	})

	got := c.resolveServices()
	if len(got) != 2 {
		t.Fatalf("resolved %d services, want 2: %+v", len(got), got)
	}
	byName := map[string]DeclaredService{}
	for _, s := range got {
		byName[s.Name] = s
	}
	if _, ok := byName["web"]; !ok {
		t.Error("the console-only service was dropped")
	}
	// The machine's own config is what its operator set, and this check is about
	// what this machine sees.
	if byName["db"].Target != "127.0.0.1:5432" {
		t.Errorf("db target = %q, want the locally declared one", byName["db"].Target)
	}
}

// With no coordinator entries the set is exactly what was declared locally —
// an older coordinator sends none, and that must change nothing.
func TestResolveFallsBackToTheLocalDeclarationsAlone(t *testing.T) {
	local := []DeclaredService{{Name: "db", Proto: "tcp", Port: 5432}}
	c := &Controller{Params: RegisterParams{Services: local}}
	if got := c.resolveServices(); len(got) != 1 || got[0].Name != "db" {
		t.Fatalf("resolved %+v, want just the local declaration", got)
	}
}

// The overlay address arrives on the netmap, delivered by a goroutine started
// AFTER the health loop. Checking before it lands leaves nothing checkable, and
// a report with no checked entries REPLACES what the coordinator holds — so
// racing it blanked the column for a full interval on every reconnect.
func TestSelfCheckWaitsForTheOverlayAddress(t *testing.T) {
	c := &Controller{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan bool, 1)
	go func() { done <- c.waitForOverlay(ctx) }()

	// Long enough for at least one poll to fire and find nothing.
	select {
	case <-done:
		t.Fatal("the self-check proceeded before any netmap delivered an overlay address")
	case <-time.After(overlayWaitPoll + 100*time.Millisecond):
	}

	c.setOverlay(netip.MustParseAddr("100.64.0.5"))
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("waitForOverlay reported failure after the address arrived")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waitForOverlay did not return once the address arrived")
	}
}

// A session that ends before any netmap must not leave the goroutine waiting.
func TestWaitForOverlayGivesUpWithTheSession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if (&Controller{}).waitForOverlay(ctx) {
		t.Error("waitForOverlay claimed success with no address")
	}
}
