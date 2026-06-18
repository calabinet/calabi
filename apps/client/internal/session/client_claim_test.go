package session

import (
	"sync"
	"sync/atomic"
	"testing"
)

// Concurrent duplicate catch-up pushes for the same tunnel must yield exactly
// one claim — the in-flight de-dup that closes the autoClaimOne TOCTOU race
// (otherwise the second claim hits the edge's "code=3001 domain already
// registered"). Run with -race to also catch a missing lock.
func TestBeginClaim_DedupsConcurrent(t *testing.T) {
	c := &Client{}
	const id = int64(946)
	const n = 64
	var granted int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if c.beginClaim(id) {
				atomic.AddInt32(&granted, 1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if granted != 1 {
		t.Fatalf("beginClaim granted %d times concurrently, want exactly 1", granted)
	}
}

// After the holder releases, the same tunnel can be claimed again — a later
// console edit or the next reconnect must not be permanently blocked.
func TestBeginClaim_ReusableAfterEnd(t *testing.T) {
	c := &Client{}
	const id = int64(1)
	if !c.beginClaim(id) {
		t.Fatal("first beginClaim should succeed")
	}
	if c.beginClaim(id) {
		t.Fatal("second beginClaim while in flight must fail")
	}
	c.endClaim(id)
	if !c.beginClaim(id) {
		t.Fatal("beginClaim should succeed again after endClaim")
	}
}

// Distinct tunnel_ids claim independently — de-dup is per tunnel.
func TestBeginClaim_IndependentTunnels(t *testing.T) {
	c := &Client{}
	if !c.beginClaim(1) || !c.beginClaim(2) {
		t.Fatal("distinct tunnel_ids must each get their own claim")
	}
}
