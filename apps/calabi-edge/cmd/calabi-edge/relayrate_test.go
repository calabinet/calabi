package main

import (
	"context"
	"log/slog"
	"sync/atomic"
	"testing"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

type fakeRelayQuota struct {
	dev, devPeak, org, orgPeak int64
	calls                      atomic.Int64
	lastOrgID                  atomic.Int64
}

func (f *fakeRelayQuota) RelayBandwidthBytesPerSec(_ context.Context, orgID int64) (int64, int64, int64, int64) {
	f.calls.Add(1)
	f.lastOrgID.Store(orgID)
	return f.dev, f.devPeak, f.org, f.orgPeak
}

func testResolver(t *testing.T, q *fakeRelayQuota) *relayRateResolver {
	t.Helper()
	return newRelayRateResolver(q, slog.New(slog.DiscardHandler))
}

// Both tiers must be installed, and both must bite. The per-device tier is the
// backstop for a client that is not limiting itself; the org tier is what the
// plan actually sells.
func TestRelayRate_BothTiersApply(t *testing.T) {
	// Device 8 MiB/s, org 8 MiB/s. Single-tier buckets carry rate×2s, so the
	// first 16 MiB clears and the next frame does not.
	const rate = 8 << 20
	q := &fakeRelayQuota{dev: rate, org: rate}
	lim := testResolver(t, q).For(42, meshproto.NodeKey{})
	if lim == nil {
		t.Fatal("a plan with relay allowance must yield a limiter")
	}
	if got := q.lastOrgID.Load(); got != 42 {
		t.Fatalf("quota looked up for org %d, want 42", got)
	}
	// Drain the buckets: 16 MiB in 1 MiB frames.
	for i := 0; i < 16; i++ {
		if !lim.Allow(1 << 20) {
			t.Fatalf("frame %d was inside the burst and must be allowed", i)
		}
	}
	if lim.Allow(1 << 20) {
		t.Fatal("the bucket is drained; the next frame must be refused")
	}
}

// Two devices of one org share the org bucket — that is the point of the tier.
// If each link got its own, an org would simply connect more devices.
func TestRelayRate_OrgBucketIsSharedAndReleased(t *testing.T) {
	const rate = 8 << 20
	q := &fakeRelayQuota{dev: rate << 4, org: rate} // device tier deliberately loose
	r := testResolver(t, q)

	a := r.For(7, meshproto.NodeKey{1})
	b := r.For(7, meshproto.NodeKey{2})
	if a == nil || b == nil {
		t.Fatal("both links must get limiters")
	}
	if r.OrgsHeld() != 1 {
		t.Fatalf("one org must hold exactly one bucket, got %d", r.OrgsHeld())
	}
	// Drain through link A; link B must find the shared bucket empty.
	for i := 0; i < 16; i++ {
		if !a.Allow(1 << 20) {
			t.Fatalf("A frame %d should fit the org burst", i)
		}
	}
	if b.Allow(1 << 20) {
		t.Fatal("B must be refused: A already spent the ORG allowance they share")
	}

	// Close releases the shared bucket, and only the last close frees it.
	a.(*relayLink).Close()
	if r.OrgsHeld() != 1 {
		t.Fatal("bucket must survive while the second link holds it")
	}
	b.(*relayLink).Close()
	if r.OrgsHeld() != 0 {
		t.Fatalf("bucket must be freed once both links are gone, %d left", r.OrgsHeld())
	}
	// Double close must not corrupt the count — the hub calls Close on
	// re-auth as well as on teardown, and a link could see both.
	a.(*relayLink).Close()
	if r.OrgsHeld() != 0 {
		t.Fatal("double close corrupted the registry")
	}
}

// Degrade-open: anything the resolver cannot decide confidently means NO limit.
// A relay that throttles because quota was unreadable is worse than one that
// briefly does not.
func TestRelayRate_DegradesOpen(t *testing.T) {
	t.Run("no meshnet (auth off / no grant)", func(t *testing.T) {
		q := &fakeRelayQuota{dev: 1 << 20, org: 1 << 20}
		if lim := testResolver(t, q).For(0, meshproto.NodeKey{}); lim != nil {
			t.Fatal("meshnet 0 means nobody to meter; must not limit")
		}
		if q.calls.Load() != 0 {
			t.Fatal("must not even ask quota without an org")
		}
	})

	t.Run("plan sets no relay allowance", func(t *testing.T) {
		q := &fakeRelayQuota{} // all zero = unlimited everywhere
		if lim := testResolver(t, q).For(42, meshproto.NodeKey{}); lim != nil {
			t.Fatal("a plan with no relay keys must not limit")
		}
	})

	t.Run("no quota client at all", func(t *testing.T) {
		if r := newRelayRateResolver(nil, slog.New(slog.DiscardHandler)); r != nil {
			t.Fatal("no quota client ⇒ no resolver ⇒ relay stays unlimited")
		}
		var nilResolver *relayRateResolver
		if lim := nilResolver.For(42, meshproto.NodeKey{}); lim != nil {
			t.Fatal("a nil resolver must answer nil, not panic")
		}
		if nilResolver.OrgsHeld() != 0 {
			t.Fatal("nil resolver holds nothing")
		}
	})
}

// Only the org tier configured (device unlimited) still has to work — the two
// tiers are independent and a plan may well set one and not the other.
func TestRelayRate_OrgTierAloneStillLimits(t *testing.T) {
	const rate = 8 << 20
	q := &fakeRelayQuota{org: rate}
	lim := testResolver(t, q).For(42, meshproto.NodeKey{})
	if lim == nil {
		t.Fatal("org-only allowance must still yield a limiter")
	}
	for i := 0; i < 16; i++ {
		if !lim.Allow(1 << 20) {
			t.Fatalf("frame %d inside the org burst", i)
		}
	}
	if lim.Allow(1 << 20) {
		t.Fatal("org bucket drained; must refuse")
	}
}
