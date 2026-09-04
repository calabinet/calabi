package mesh

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/calabi/calabi/pkg/mesh-proto/meshpb"
	"github.com/calabi/calabi/pkg/mesh-proto/stun"
)

// startSTUNResponder runs a loopback STUN server that answers binding requests
// after `delay`, so a test can order two regions by measured RTT.
func startSTUNResponder(t *testing.T, delay time.Duration) netip.AddrPort {
	t.Helper()
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := srv.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			tx, ok := stun.IsBindingRequest(buf[:n])
			if !ok {
				continue
			}
			resp := stun.BindingResponse(tx, netip.AddrPortFrom(from.Addr().Unmap(), from.Port()))
			go func(to netip.AddrPort) {
				time.Sleep(delay)
				_, _ = srv.WriteToUDPAddrPort(resp, to)
			}(from)
		}
	}()
	ap := srv.LocalAddr().(*net.UDPAddr).AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

func regionAt(code string, ap netip.AddrPort) DERPRegion {
	return DERPRegion{Code: code, Nodes: []DERPNode{{
		HostName: ap.Addr().String(), DERPPort: 3340, STUNPort: int(ap.Port()),
	}}}
}

// probeRegions measures every region that answers, orders them by RTT, and drops
// the ones that don't reply at all — an unreachable relay must never become home.
func TestProbeRegionsMeasuresAndOrders(t *testing.T) {
	fast := startSTUNResponder(t, 0)
	slow := startSTUNResponder(t, 120*time.Millisecond)

	disco, _ := GenerateDiscoKey()
	ms, err := newMagicSock(disco, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer ms.Close()

	m := DERPMap{Regions: []DERPRegion{
		regionAt("slow", slow),
		regionAt("fast", fast),
		// TEST-NET-1 is unrouted: this region can't answer.
		{Code: "dead", Nodes: []DERPNode{{HostName: "203.0.113.1", DERPPort: 3340, STUNPort: 3478}}},
		// No STUN port at all: not measurable, so not eligible.
		{Code: "nostun", Nodes: []DERPNode{{HostName: "127.0.0.1", DERPPort: 3340}}},
	}}
	got := probeRegions(context.Background(), ms, m, slog.Default())
	if len(got) != 2 {
		t.Fatalf("measured %d regions (%+v), want just the two that answered", len(got), got)
	}
	if got[0].Region != "fast" || got[1].Region != "slow" {
		t.Fatalf("order = %s,%s; want fast,slow (ascending RTT)", got[0].Region, got[1].Region)
	}
	if got[0].RTT >= got[1].RTT {
		t.Fatalf("RTTs not ordered: %v >= %v", got[0].RTT, got[1].RTT)
	}
	if got[0].STUN != fast {
		t.Fatalf("winner's STUN endpoint = %s, want %s", got[0].STUN, fast)
	}
	// The chosen region's STUN endpoint is what reflexive discovery then uses.
	if sa, ok := stunFor("fast", got); !ok || sa != fast {
		t.Fatalf("stunFor(fast) = %s ok=%v, want %s", sa, ok, fast)
	}
	if _, ok := stunFor("dead", got); ok {
		t.Fatal("stunFor returned an endpoint for a region that never answered")
	}
}

func TestPickHome(t *testing.T) {
	measured := []regionRTT{
		{Region: "sgp", RTT: 20 * time.Millisecond},
		{Region: "tyo", RTT: 30 * time.Millisecond},
		{Region: "lax", RTT: 150 * time.Millisecond},
	}
	// A map that mixes platform regions with one self-hosted relay, to exercise
	// the affinity co-switch: "own" homes on the self- region, "platform" avoids it.
	withOwn := []regionRTT{
		{Region: "self-acme-tyo", RTT: 40 * time.Millisecond},
		{Region: "sgp", RTT: 20 * time.Millisecond},
		{Region: "lax", RTT: 150 * time.Millisecond},
	}
	// Two self-hosted facilities — the case the class preference alone cannot
	// tell apart, because both relays are "own".
	twoOwn := []regionRTT{
		{Region: "self-cd-vps-02", RTT: 12 * time.Millisecond},
		{Region: "self-cd-vps", RTT: 31 * time.Millisecond},
	}
	cases := []struct {
		name    string
		current string
		in      []regionRTT
		pref    homePref
		pinned  string
		want    string
	}{
		{"nothing measured keeps the coordinator's default", "lax", nil, homeAnyRelay, "", ""},
		{"no home yet takes the fastest", "", measured, homeAnyRelay, "", "sgp"},
		{"a far home is replaced", "lax", measured, homeAnyRelay, "", "sgp"},
		{"the fastest home stays", "sgp", measured, homeAnyRelay, "", "sgp"},
		{"a home that didn't answer is replaced", "fra", measured, homeAnyRelay, "", "sgp"},
		{
			// 30ms vs 20ms is a real 10ms difference but under the hysteresis margin:
			// re-homing rewrites every peer's netmap, so near-ties must not flap.
			"a near-tie keeps the current home", "tyo", measured, homeAnyRelay, "", "tyo",
		},
		{
			"a materially faster region wins", "tyo",
			[]regionRTT{{Region: "sgp", RTT: 5 * time.Millisecond}, {Region: "tyo", RTT: 30 * time.Millisecond}},
			homeAnyRelay, "", "sgp",
		},
		// --- affinity co-switch (requirement #1) ---
		{
			// "own" prefers the self-hosted relay even though a platform region is
			// faster — that's the point: use my node.
			"own homes on the self-hosted relay despite higher RTT", "", withOwn, homePreferOwn, "", "self-acme-tyo",
		},
		{
			// Flipping to "own" while homed on a platform region switches
			// IMMEDIATELY: the platform home is no longer a candidate, so hysteresis
			// can't hold it.
			"own switches away from a platform home at once", "sgp", withOwn, homePreferOwn, "", "self-acme-tyo",
		},
		{
			// "platform" excludes the self- region and takes the fastest platform one.
			"platform avoids the self-hosted relay", "self-acme-tyo", withOwn, homePreferPlatform, "", "sgp",
		},
		{
			// "own" but the org's relay didn't answer (or none exists): never strand
			// the node — fall back to the fastest reachable (platform) region.
			"own falls back to platform when no self- region is measurable", "lax", measured, homePreferOwn, "", "sgp",
		},
		// --- facility pin: the relay follows the EDGE to the same box ---
		{
			// The reported bug. Both relays are the org's own, so the class
			// preference cannot separate them and the faster one wins — leaving
			// the relay at cd-vps-02 while the edge sits at cd-vps.
			"without a pin the faster self-hosted relay wins", "self-cd-vps-02", twoOwn, homePreferOwn, "", "self-cd-vps-02",
		},
		{
			// With the pin, the slower relay in the edge's facility is chosen —
			// 19ms slower and still correct: the operator placed both roles there.
			"the pinned facility wins over a faster sibling", "self-cd-vps-02", twoOwn, homePreferOwn, "self-cd-vps", "self-cd-vps",
		},
		{
			"the pin also beats hysteresis on the current home", "self-cd-vps-02", twoOwn, homeAnyRelay, "self-cd-vps", "self-cd-vps",
		},
		{
			// Soft: a pinned facility whose relay is down must not strand the node.
			"an unreachable pin falls back to measurement", "", twoOwn, homePreferOwn, "self-fra", "self-cd-vps-02",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pickHome(tc.current, tc.in, tc.pref, tc.pinned); got != tc.want {
				t.Fatalf("pickHome(%q, pref=%d, pinned=%q) = %q, want %q", tc.current, tc.pref, tc.pinned, got, tc.want)
			}
		})
	}
}

// FacilityRelayRegion is the edge-region → relay-region mapping that makes the
// pin possible: an edge that also runs a relay labels it after its own region.
func TestFacilityRelayRegion(t *testing.T) {
	cases := []struct {
		name           string
		edgeRegion     string
		preferPlatform bool
		want           string
	}{
		{"self-hosted facility", "cd-vps", false, "self-cd-vps"},
		{"the other facility", "cd-vps-02", false, "self-cd-vps-02"},
		{"platform data plane is not pinned", "lax", true, ""},
		{"no anchored region yet", "", false, ""},
		{"whitespace is not a region", "  ", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := FacilityRelayRegion(tc.edgeRegion, tc.preferPlatform); got != tc.want {
				t.Fatalf("FacilityRelayRegion(%q, %v) = %q, want %q", tc.edgeRegion, tc.preferPlatform, got, tc.want)
			}
		})
	}
}

func TestRegionSTUNHostPort(t *testing.T) {
	r := DERPRegion{Code: "lax", Nodes: []DERPNode{
		{HostName: "no-stun.example.net", DERPPort: 3340},
		{HostName: "derp-lax.example.net", DERPPort: 3340, STUNPort: 3478},
	}}
	hp, ok := regionSTUNHostPort(r)
	if !ok || hp != net.JoinHostPort("derp-lax.example.net", strconv.Itoa(3478)) {
		t.Fatalf("got %q ok=%v, want derp-lax.example.net:3478", hp, ok)
	}
	if _, ok := regionSTUNHostPort(DERPRegion{Code: "x", Nodes: []DERPNode{{HostName: "h", DERPPort: 3340}}}); ok {
		t.Fatal("a region with no STUN port must not be measurable")
	}
	if _, ok := regionSTUNHostPort(DERPRegion{Code: "empty"}); ok {
		t.Fatal("a region with no relays must not be measurable")
	}
}

// The controller measures the fleet on its first netmap and reports the region it
// found fastest as its home — replacing the coordinator's deployment-wide default.
func TestControllerReportsMeasuredHome(t *testing.T) {
	fast := startSTUNResponder(t, 0)
	slow := startSTUNResponder(t, 120*time.Millisecond)

	c := &Controller{Logger: slog.Default()}
	// Seed as the netmap would: coordinator says "slow", the map lists both.
	m := DERPMap{Regions: []DERPRegion{regionAt("slow", slow), regionAt("fast", fast)}}
	if !c.setDERPMap(m, "slow") {
		t.Fatal("a first DERP map should trigger a measurement")
	}
	if c.getHome() != "slow" {
		t.Fatalf("home seeded as %q, want the coordinator's stamp %q", c.getHome(), "slow")
	}
	if c.setDERPMap(m, "slow") {
		t.Fatal("an unchanged DERP map should not trigger a re-measurement")
	}

	disco, _ := GenerateDiscoKey()
	ms, err := newMagicSock(disco, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer ms.Close()

	f := &fakeCoord{reg: &meshpb.RegisterNodeResponse{NodeId: 7}}
	c.Coord = dialFake(t, f)
	c.homeProbe(context.Background(), 7, ms)

	if got := c.getHome(); got != "fast" {
		t.Fatalf("home after measuring = %q, want fast", got)
	}
	// The chosen region's STUN endpoint becomes the reflexive-probe target.
	if got := c.getStunServer(); got != fast {
		t.Fatalf("stun server = %s, want the home region's %s", got, fast)
	}
	// A changed home is reported immediately, not at the next tick.
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reportedHome) == 0 || f.reportedHome[len(f.reportedHome)-1] != "fast" {
		t.Fatalf("coordinator received homes %v, want the measured one reported", f.reportedHome)
	}
}
