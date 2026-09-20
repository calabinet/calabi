package ratelimit

import (
	"io"
	"sync"
	"testing"
	"time"
)

// writeMB writes n MiB through w in 1 MiB chunks and returns how long it took.
func writeMB(tb testing.TB, w io.Writer, n int) time.Duration {
	tb.Helper()
	buf := make([]byte, 1<<20)
	start := time.Now()
	for i := 0; i < n; i++ {
		if _, err := w.Write(buf); err != nil {
			tb.Fatalf("write: %v", err)
		}
	}
	return time.Since(start)
}

// The org tier is the whole point of the two-tier design, and the only way to
// show it works is to prove that traffic which the per-tunnel tier would have
// let through gets held back once the tunnels share an org bucket.
//
// Sizing: a single-tier Limiter's bucket is rate × DefaultBurstSeconds (2s), so
// 8 MiB/s carries a 16 MiB burst. Two tunnels writing 10 MiB each is 20 MiB
// total: comfortably inside each tunnel's own burst (so tier one alone finishes
// at memory speed), and 4 MiB past the shared org burst — which at 8 MiB/s is
// half a second of unavoidable waiting.
const (
	testRate    = 8 << 20 // bytes/sec
	testPerSide = 10      // MiB each side writes
)

func TestChain_OrgTierBoundsTheSumOfTunnels(t *testing.T) {
	mkTunnel := func() *Limiter { return New(testRate, 0) }

	// Tier one only: each tunnel has its own bucket, nothing above them.
	// This is exactly the pre-2026-09-20 behaviour and it must be FAST —
	// otherwise the contrast below proves nothing.
	var wg sync.WaitGroup
	soloStart := time.Now()
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			writeMB(t, NewChain(mkTunnel(), nil).Writer(io.Discard), testPerSide)
		}()
	}
	wg.Wait()
	solo := time.Since(soloStart)
	if solo > 200*time.Millisecond {
		t.Fatalf("per-tunnel tier alone should not throttle 10 MiB (inside its %d-byte burst); took %v",
			testRate*DefaultBurstSeconds, solo)
	}

	// Same two tunnels, now sharing one org bucket. 20 MiB against a 16 MiB
	// burst refilling at 8 MiB/s ⇒ ~500 ms of waiting that cannot be skipped.
	org := New(testRate, 0)
	sharedStart := time.Now()
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			writeMB(t, NewChain(mkTunnel(), org).Writer(io.Discard), testPerSide)
		}()
	}
	wg.Wait()
	shared := time.Since(sharedStart)
	if shared < 300*time.Millisecond {
		t.Fatalf("org tier did not bound the two tunnels: 20 MiB through an %d B/s org bucket took only %v",
			int64(testRate), shared)
	}
}

func TestChain_NilAndUnlimitedArePassThrough(t *testing.T) {
	var nilChain *Chain
	if got := nilChain.Writer(io.Discard); got != io.Writer(io.Discard) {
		t.Fatal("nil Chain must return the writer untouched")
	}
	if got := nilChain.Reader(io.LimitReader(nil, 0)); got == nil {
		t.Fatal("nil Chain must return the reader untouched")
	}
	// Both tiers unconfigured: Limiter.Writer already passes through, so the
	// chain must too — no wrapper allocated, no wait taken.
	c := NewChain(New(0, 0), New(0, 0))
	if got := c.Writer(io.Discard); got != io.Writer(io.Discard) {
		t.Fatal("unlimited tiers must not wrap the writer")
	}
	if d := writeMB(t, c.Writer(io.Discard), 4); d > 100*time.Millisecond {
		t.Fatalf("unlimited chain throttled: %v", d)
	}
}

func TestOrgRegistry_SharesOneBucketPerOrg(t *testing.T) {
	r := NewOrgRegistry()
	a := r.Acquire(7, testRate, 0)
	b := r.Acquire(7, testRate, 0)
	if a == nil || a != b {
		t.Fatalf("same org must get the same bucket; got %p and %p", a, b)
	}
	if other := r.Acquire(8, testRate, 0); other == a {
		t.Fatal("different orgs must not share a bucket")
	}
	if r.Len() != 2 {
		t.Fatalf("want 2 orgs held, got %d", r.Len())
	}
}

func TestOrgRegistry_FreesOnLastRelease(t *testing.T) {
	r := NewOrgRegistry()
	r.Acquire(7, testRate, 0)
	r.Acquire(7, testRate, 0)
	r.Release(7)
	if r.Len() != 1 {
		t.Fatal("bucket must survive while another session holds it")
	}
	r.Release(7)
	if r.Len() != 0 {
		t.Fatalf("bucket must be freed on the last release; %d left", r.Len())
	}
	// Over-release must not go negative or panic — a double Release is a bug
	// in the caller, but it must not take the edge down with it.
	r.Release(7)
	if r.Len() != 0 {
		t.Fatal("over-release corrupted the registry")
	}
}

// A session arriving with fresher quota (plan change, admin override) must
// RE-RATE the shared bucket, not swap in a new one: sessions already holding
// the old pointer would otherwise keep limiting against a bucket nobody else
// shares, which is the org cap quietly failing open.
func TestOrgRegistry_HotSwapsRatesInPlace(t *testing.T) {
	r := NewOrgRegistry()
	first := r.Acquire(7, testRate, 0)
	second := r.Acquire(7, testRate*2, testRate*4)
	if first != second {
		t.Fatal("changed rates must re-rate the SAME bucket, not replace it")
	}
	if got := first.Rate(); got != testRate*2 {
		t.Fatalf("sustained not applied: want %d, got %d", testRate*2, got)
	}
	if got := first.PeakRate(); got != testRate*4 {
		t.Fatalf("peak not applied: want %d, got %d", testRate*4, got)
	}
}

func TestOrgRegistry_NoOrgTierForUnresolvedTenant(t *testing.T) {
	r := NewOrgRegistry()
	if l := r.Acquire(0, testRate, 0); l != nil {
		t.Fatal("org id 0 (dev / static-YAML tenant) must get no org tier")
	}
	r.Release(0) // must not panic
	if r.Len() != 0 {
		t.Fatal("org id 0 must not occupy a slot")
	}
	var nilReg *OrgRegistry
	if l := nilReg.Acquire(7, testRate, 0); l != nil {
		t.Fatal("nil registry must yield no org tier")
	}
	nilReg.Release(7) // must not panic
	if nilReg.Len() != 0 {
		t.Fatal("nil registry Len must be 0")
	}
}
