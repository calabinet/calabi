package mobile

import (
	"encoding/json"
	"errors"
	"math/big"
	"net/netip"
	"reflect"
	"sync"
	"testing"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// fakePlatform records what the core asks of the app.
type fakePlatform struct {
	mu       sync.Mutex
	applied  []networkSettings
	nextFD   int32
	sameFD   bool // answer every ApplyNetwork with the same descriptor, like iOS
	applyErr error
	ifaces   string
}

func (p *fakePlatform) ApplyNetwork(js string) (int32, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.applyErr != nil {
		return -1, p.applyErr
	}
	var s networkSettings
	if err := json.Unmarshal([]byte(js), &s); err != nil {
		return -1, err
	}
	p.applied = append(p.applied, s)
	if !p.sameFD || p.nextFD == 0 {
		p.nextFD++
	}
	return p.nextFD, nil
}

func (p *fakePlatform) Protect(int32) bool { return true }

func (p *fakePlatform) Interfaces() (string, error) {
	if p.ifaces == "" {
		return `[{"name":"wlan0","up":true,"addrs":["192.0.2.7/24"]}]`, nil
	}
	return p.ifaces, nil
}

func (p *fakePlatform) Log(int32, string) {}

func (p *fakePlatform) settings() []networkSettings {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]networkSettings(nil), p.applied...)
}

// newTestRouting builds a vpnRouting whose descriptors open as in-memory tuns,
// counting the opens.
func newTestRouting(p *fakePlatform) (*vpnRouting, *swapTUN, *int) {
	st := newSwapTUN(1280)
	r := newVPNRouting(p, st, 1280)
	opens := 0
	r.open = func(int) (tun.Device, error) {
		opens++
		return tuntest.NewChannelTUN().TUN(), nil
	}
	return r, st, &opens
}

func TestVPNRoutingWaitsForAnAddress(t *testing.T) {
	p := &fakePlatform{}
	r, st, _ := newTestRouting(p)
	defer st.Close()

	// Routes can arrive before the address; a VPN cannot be established without
	// one, so they are held and go out with it.
	if err := r.AddSubnetRoutes([]netip.Prefix{netip.MustParsePrefix("10.99.0.0/16")}); err != nil {
		t.Fatal(err)
	}
	if n := len(p.settings()); n != 0 {
		t.Fatalf("applied %d times before any address", n)
	}
	if err := r.ConfigureLink(netip.MustParseAddr("100.64.0.9")); err != nil {
		t.Fatal(err)
	}
	got := p.settings()
	want := networkSettings{
		Addresses: []string{"100.64.0.9/32"},
		Routes:    []string{"10.99.0.0/16", "100.64.0.0/10"},
		MTU:       1280,
	}
	if len(got) != 1 || !reflect.DeepEqual(got[0], want) {
		t.Fatalf("applied %+v, want once %+v", got, want)
	}
}

func TestVPNRoutingAppliesEveryChangeAndOnlyChanges(t *testing.T) {
	p := &fakePlatform{}
	r, st, opens := newTestRouting(p)
	defer st.Close()
	overlay := netip.MustParseAddr("100.64.0.9")
	subnet := netip.MustParsePrefix("10.99.0.0/16")

	_ = r.ConfigureLink(overlay)
	_ = r.ConfigureLink(overlay) // unchanged: not re-applied
	_ = r.AddSubnetRoutes([]netip.Prefix{subnet})
	cleanup, err := r.EnableExitRoutes(nil, []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")})
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	_ = r.DelSubnetRoutes([]netip.Prefix{subnet})

	got := p.settings()
	if len(got) != 5 {
		t.Fatalf("applied %d times, want 5 (link, subnet, exit on, exit off, subnet off)", len(got))
	}
	exitRoutes := got[2].Routes
	if !containsRoute(exitRoutes, "100.64.0.0/10") || !containsRoute(exitRoutes, "10.99.0.0/16") {
		t.Errorf("exit routes %v lost the overlay or the subnet", exitRoutes)
	}
	if covers(exitRoutes, netip.MustParseAddr("192.168.1.1")) {
		t.Errorf("exit routes %v send the kept LAN into the VPN", exitRoutes)
	}
	if !covers(exitRoutes, netip.MustParseAddr("8.8.8.8")) {
		t.Errorf("exit routes %v leave the internet outside the VPN", exitRoutes)
	}
	if !reflect.DeepEqual(got[4].Routes, []string{"100.64.0.0/10"}) {
		t.Errorf("after withdrawing everything, routes = %v, want only the overlay", got[4].Routes)
	}
	// Android: every establish is a new descriptor, so every apply swaps.
	if *opens != 5 {
		t.Errorf("opened %d descriptors, want 5", *opens)
	}
}

// iOS keeps one descriptor across settings changes. Opening it again would
// close it from under the datapath when the old device is swapped away.
func TestVPNRoutingKeepsTheSameDescriptor(t *testing.T) {
	p := &fakePlatform{sameFD: true}
	r, st, opens := newTestRouting(p)
	defer st.Close()
	_ = r.ConfigureLink(netip.MustParseAddr("100.64.0.9"))
	_ = r.AddSubnetRoutes([]netip.Prefix{netip.MustParsePrefix("10.99.0.0/16")})
	if len(p.settings()) != 2 {
		t.Fatalf("applied %d times, want 2", len(p.settings()))
	}
	if *opens != 1 {
		t.Fatalf("opened the descriptor %d times, want once", *opens)
	}
}

func TestVPNRoutingReportsAPlatformRefusal(t *testing.T) {
	p := &fakePlatform{applyErr: errors.New("VPN permission revoked")}
	r, st, _ := newTestRouting(p)
	defer st.Close()
	if err := r.ConfigureLink(netip.MustParseAddr("100.64.0.9")); err == nil {
		t.Fatal("a refused establish was not reported")
	}
}

// subtractPrefixes must cover exactly base minus remove: every address outside
// the removed prefixes, and none inside, with no overlaps.
func TestSubtractPrefixes(t *testing.T) {
	all := netip.MustParsePrefix("0.0.0.0/0")
	remove := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
	}
	got := subtractPrefixes(all, remove)

	total := new(big.Int)
	for _, p := range got {
		size := new(big.Int).Lsh(big.NewInt(1), uint(32-p.Bits()))
		total.Add(total, size)
		for _, rm := range remove {
			if p.Overlaps(rm) {
				t.Errorf("%v overlaps removed %v", p, rm)
			}
		}
	}
	want := new(big.Int).Lsh(big.NewInt(1), 32)
	want.Sub(want, big.NewInt(1<<24+1<<20+1<<16))
	if total.Cmp(want) != 0 {
		t.Errorf("result covers %v addresses, want %v (all of IPv4 minus the three blocks)", total, want)
	}
	for i := range got {
		for j := i + 1; j < len(got); j++ {
			if got[i].Overlaps(got[j]) {
				t.Errorf("%v overlaps %v", got[i], got[j])
			}
		}
	}

	if r := subtractPrefixes(netip.MustParsePrefix("10.1.0.0/16"), remove); r != nil {
		t.Errorf("a base inside a removed block left %v", r)
	}
	if r := subtractPrefixes(netip.MustParsePrefix("8.8.0.0/16"), remove); !reflect.DeepEqual(r, []netip.Prefix{netip.MustParsePrefix("8.8.0.0/16")}) {
		t.Errorf("a base touching nothing removed became %v", r)
	}
}

func containsRoute(routes []string, want string) bool {
	for _, r := range routes {
		if r == want {
			return true
		}
	}
	return false
}

func covers(routes []string, a netip.Addr) bool {
	for _, r := range routes {
		if netip.MustParsePrefix(r).Contains(a) {
			return true
		}
	}
	return false
}
