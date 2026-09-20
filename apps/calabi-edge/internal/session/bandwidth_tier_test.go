package session

import (
	"testing"

	"github.com/calabinet/calabi/apps/calabi-edge/internal/ratelimit"
)

// Before 2026-09-20 the bucket lived on the SESSION, so two tunnels on one
// client connection shared it. Now each tunnel gets its own, and the shared
// thing is the org bucket one level up. Both halves of that swap are asserted
// here because getting either backwards silently changes what a customer gets:
// sharing the tunnel bucket would halve a two-tunnel session, and NOT sharing
// the org bucket would hand every tunnel the full org allowance.
func TestLimiterFor_TunnelBucketsAreSeparateOrgBucketIsShared(t *testing.T) {
	s := &Session{}
	s.SetBandwidthLimit(8<<20, 0)
	org := ratelimit.New(8<<20, 0)
	s.SetOrgLimiter(org)

	for _, id := range []string{"tun-a", "tun-b"} {
		if !s.RegisterProxy(&Proxy{ID: id}) {
			t.Fatalf("register %s", id)
		}
	}
	a, b := s.LimiterFor("tun-a"), s.LimiterFor("tun-b")

	if a.Tunnel() == nil || b.Tunnel() == nil {
		t.Fatal("every registered tunnel must get its own bucket")
	}
	if a.Tunnel() == b.Tunnel() {
		t.Fatal("two tunnels must NOT share one per-tunnel bucket (that was the old per-session behaviour)")
	}
	if a.Org() != org || b.Org() != org {
		t.Fatal("both tunnels must draw from the SAME org bucket")
	}
}

// A visitor connection can outlive the proxy's teardown by a hair and land
// here with an id the session no longer knows. It must still be limited by the
// org tier rather than escaping unlimited — and it must not panic.
func TestLimiterFor_UnknownProxyStillCarriesTheOrgTier(t *testing.T) {
	s := &Session{}
	org := ratelimit.New(8<<20, 0)
	s.SetOrgLimiter(org)

	c := s.LimiterFor("never-registered")
	if c == nil {
		t.Fatal("LimiterFor must never return nil")
	}
	if c.Tunnel() != nil {
		t.Fatal("unknown proxy has no per-tunnel bucket")
	}
	if c.Org() != org {
		t.Fatal("unknown proxy must still be bound by the org tier")
	}
}

// The handshake resolves quota BEFORE the client may open a proxy, and
// RegisterProxy builds the tunnel's bucket from whatever rates the session
// holds at that moment. Pin the ordering: a proxy registered before any rate
// is known is unlimited at tier one, and one registered after is not. If this
// ever inverts, every tunnel silently loses its own cap and only the org tier
// remains.
func TestRegisterProxy_BuildsTunnelBucketFromCurrentRates(t *testing.T) {
	s := &Session{}

	if !s.RegisterProxy(&Proxy{ID: "before"}) {
		t.Fatal("register before")
	}
	if l := s.LimiterFor("before").Tunnel(); l != nil {
		t.Fatalf("no rates known yet ⇒ unlimited tunnel tier, got %d B/s", l.Rate())
	}

	s.SetBandwidthLimit(8<<20, 16<<20)
	if !s.RegisterProxy(&Proxy{ID: "after"}) {
		t.Fatal("register after")
	}
	l := s.LimiterFor("after").Tunnel()
	if l == nil {
		t.Fatal("rates were set before registration; the tunnel must have a bucket")
	}
	if got := l.Rate(); got != 8<<20 {
		t.Fatalf("sustained: want %d, got %d", 8<<20, got)
	}
	if got := l.PeakRate(); got != 16<<20 {
		t.Fatalf("peak: want %d, got %d", 16<<20, got)
	}
}

// No org limiter (standalone edge, or a tenant whose id is not numeric) must
// leave the org tier off rather than fabricating a zero-rate bucket — a
// zero-rate Limiter is "unlimited" here, but relying on that by accident is
// how a real cap gets skipped later.
func TestLimiterFor_NoOrgTierWhenUnset(t *testing.T) {
	s := &Session{}
	s.SetBandwidthLimit(8<<20, 0)
	if !s.RegisterProxy(&Proxy{ID: "solo"}) {
		t.Fatal("register")
	}
	if got := s.LimiterFor("solo").Org(); got != nil {
		t.Fatal("org tier must stay nil when none was installed")
	}
	if s.OrgLimiter() != nil {
		t.Fatal("OrgLimiter must report nil")
	}
}
