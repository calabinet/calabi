package listener

import (
	"context"
	"log/slog"
	"testing"

	"github.com/calabinet/calabi/apps/calabi-edge/internal/ratelimit"
	"github.com/calabinet/calabi/apps/calabi-edge/internal/session"
)

type fixedCaps struct{ caps BandwidthCaps }

func (f fixedCaps) BandwidthLimitsBytesPerSec(context.Context, string, string) BandwidthCaps {
	return f.caps
}

// countingOrgRegistry records what the handshake asked of the registry, so a
// test can assert the acquire/release pairing without reaching into
// ratelimit's internals.
type countingOrgRegistry struct {
	reg      *ratelimit.OrgRegistry
	acquired []int64
	released []int64
	lastRate [2]int64
}

func (c *countingOrgRegistry) Acquire(orgID, sustainedBps, peakBps int64) *ratelimit.Limiter {
	c.acquired = append(c.acquired, orgID)
	c.lastRate = [2]int64{sustainedBps, peakBps}
	return c.reg.Acquire(orgID, sustainedBps, peakBps)
}

func (c *countingOrgRegistry) Release(orgID int64) {
	c.released = append(c.released, orgID)
	c.reg.Release(orgID)
}

func newTestControl(t *testing.T, caps BandwidthCaps, reg OrgBandwidthRegistry) *Control {
	t.Helper()
	return NewControl(slog.New(slog.DiscardHandler), ControlOptions{
		BandwidthResolver: fixedCaps{caps: caps},
		OrgBandwidth:      reg,
	})
}

// The handshake must install BOTH tiers and hand back a release that frees the
// org bucket. A leaked refcount here does not break traffic — it keeps the
// bucket (and the org's entry) alive forever, which only shows up as an edge
// that slowly accumulates them over weeks of uptime.
func TestInstallBandwidth_InstallsBothTiersAndReleasesTheOrgOne(t *testing.T) {
	reg := &countingOrgRegistry{reg: ratelimit.NewOrgRegistry()}
	c := newTestControl(t, BandwidthCaps{
		Sustained: 1 << 20, Peak: 2 << 20,
		OrgSustained: 4 << 20, OrgPeak: 8 << 20,
	}, reg)

	sess := &session.Session{TenantID: "42"}
	release := c.installBandwidth(context.Background(), sess, "42", "ws")
	if release == nil {
		t.Fatal("a session with an org tier must hand back a release")
	}
	if sess.OrgLimiter() == nil {
		t.Fatal("org tier not installed on the session")
	}
	if len(reg.acquired) != 1 || reg.acquired[0] != 42 {
		t.Fatalf("want one acquire for org 42, got %v", reg.acquired)
	}
	if reg.lastRate != [2]int64{4 << 20, 8 << 20} {
		t.Fatalf("org rates not passed through: %v", reg.lastRate)
	}
	// Per-tunnel tier lands on proxies registered after the handshake.
	if !sess.RegisterProxy(&session.Proxy{ID: "t1"}) {
		t.Fatal("register proxy")
	}
	tun := sess.LimiterFor("t1").Tunnel()
	if tun == nil || tun.Rate() != 1<<20 {
		t.Fatalf("per-tunnel tier not installed: %+v", tun)
	}

	release()
	if len(reg.released) != 1 || reg.released[0] != 42 {
		t.Fatalf("want one release for org 42, got %v", reg.released)
	}
	if reg.reg.Len() != 0 {
		t.Fatalf("org bucket leaked: %d still held", reg.reg.Len())
	}
}

// Two sessions of the same org share one bucket and it survives until both are
// gone. This is the case the org tier exists for — if each session got its own
// bucket, an org would simply open more connections to get more bandwidth,
// which is the very hole being closed.
func TestInstallBandwidth_SessionsOfOneOrgShareAndOutliveEachOther(t *testing.T) {
	reg := &countingOrgRegistry{reg: ratelimit.NewOrgRegistry()}
	c := newTestControl(t, BandwidthCaps{Sustained: 1 << 20, OrgSustained: 4 << 20}, reg)

	a := &session.Session{TenantID: "7"}
	b := &session.Session{TenantID: "7"}
	relA := c.installBandwidth(context.Background(), a, "7", "")
	relB := c.installBandwidth(context.Background(), b, "7", "")

	if a.OrgLimiter() == nil || a.OrgLimiter() != b.OrgLimiter() {
		t.Fatal("two sessions of one org must share the SAME org bucket")
	}
	relA()
	if reg.reg.Len() != 1 {
		t.Fatal("bucket must survive while the second session still holds it")
	}
	if b.OrgLimiter() == nil {
		t.Fatal("the surviving session must still be limited")
	}
	relB()
	if reg.reg.Len() != 0 {
		t.Fatalf("bucket must be freed once both sessions end; %d left", reg.reg.Len())
	}
}

// Degrade-open paths: no resolver, a tenant with no numeric org, and a plan
// with no org allowance must all leave the org tier off rather than installing
// a zero-rate one. An edge that throttles because quota could not be read is
// worse than one that briefly does not.
func TestInstallBandwidth_DegradesOpen(t *testing.T) {
	t.Run("no resolver", func(t *testing.T) {
		c := NewControl(slog.New(slog.DiscardHandler), ControlOptions{})
		sess := &session.Session{TenantID: "42"}
		if release := c.installBandwidth(context.Background(), sess, "42", ""); release != nil {
			t.Fatal("no resolver ⇒ nothing to release")
		}
		if sess.OrgLimiter() != nil {
			t.Fatal("no resolver ⇒ no org tier")
		}
	})

	t.Run("non-numeric tenant", func(t *testing.T) {
		reg := &countingOrgRegistry{reg: ratelimit.NewOrgRegistry()}
		c := newTestControl(t, BandwidthCaps{Sustained: 1 << 20, OrgSustained: 4 << 20}, reg)
		sess := &session.Session{TenantID: "dev"}
		if release := c.installBandwidth(context.Background(), sess, "dev", ""); release != nil {
			t.Fatal("a tenant with no org id must not acquire an org bucket")
		}
		if len(reg.acquired) != 0 {
			t.Fatalf("registry must not be touched: %v", reg.acquired)
		}
	})

	t.Run("plan without an org allowance", func(t *testing.T) {
		reg := &countingOrgRegistry{reg: ratelimit.NewOrgRegistry()}
		c := newTestControl(t, BandwidthCaps{Sustained: 1 << 20}, reg)
		sess := &session.Session{TenantID: "42"}
		if release := c.installBandwidth(context.Background(), sess, "42", ""); release != nil {
			t.Fatal("org_bandwidth_kbps absent (old plan row) ⇒ no org tier")
		}
		if sess.OrgLimiter() != nil {
			t.Fatal("org tier must stay off for a plan that does not set it")
		}
		// The per-tunnel tier still applies.
		if !sess.RegisterProxy(&session.Proxy{ID: "t1"}) {
			t.Fatal("register proxy")
		}
		if tun := sess.LimiterFor("t1").Tunnel(); tun == nil || tun.Rate() != 1<<20 {
			t.Fatal("per-tunnel tier must be unaffected by the org tier being off")
		}
	})
}
