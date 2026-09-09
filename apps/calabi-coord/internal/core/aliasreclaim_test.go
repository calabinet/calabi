package core

import (
	"context"
	"net/netip"
	"testing"
)

// A restart must not burn the pool. The allocator lives in memory and is warmed
// from what the STORE still holds, so anything released before the restart is
// held by nobody — and must come back, not fall below a high-water mark and
// vanish. Over enough restarts that is a monotonic burn of a /11.
func TestAliasPoolReclaimsReleasedBlocksAcrossRestart(t *testing.T) {
	ctx := context.Background()
	lan := netip.MustParsePrefix("192.168.1.0/24")

	p := NewMemAliasIPAM()
	var got []netip.Prefix
	for i := 0; i < 5; i++ {
		a, err := p.Allocate(ctx, 1, lan)
		if err != nil {
			t.Fatalf("allocate %d: %v", i, err)
		}
		got = append(got, a)
	}
	// Four nodes withdraw their routes; one keeps its alias.
	kept := got[4]
	for _, a := range got[:4] {
		if err := p.Release(ctx, a); err != nil {
			t.Fatalf("release: %v", err)
		}
	}

	// Restart: a fresh allocator, warmed from the one alias the store still has.
	p2 := NewMemAliasIPAM()
	p2.Warm([]netip.Prefix{kept})

	// The measure that matters is capacity, not which block comes back first:
	// everything except the one still-held /24 must be free again.
	poolAddrs := uint64(1) << uint(32-overlayAliasPool.Bits())
	if got, want := p2.FreeAddrs(), poolAddrs-256; got != want {
		t.Fatalf("free after restart = %d addresses, want %d (pool minus the one held /24) — %d were burned",
			got, want, int64(want)-int64(got))
	}
	// And they are reachable, not merely counted: the four released /24s were
	// contiguous and aligned, so the pool should hand back the /22 over them.
	blk, err := p2.Allocate(ctx, 1, netip.MustParsePrefix("10.0.0.0/22"))
	if err != nil {
		t.Fatalf("allocate /22 over the reclaimed run: %v", err)
	}
	if want := netip.MustParsePrefix("100.96.0.0/22"); blk != want {
		t.Fatalf("got %v, want %v — the released blocks did not come back coalesced", blk, want)
	}
}

// A host route's alias is one address out of a /24 BLOCK, and the block is the
// unit that left the pool: reconcileAliases reuses it for the node's other host
// routes, and releasable() hands the whole block back when the last one goes. So
// a warm that only reserves the /32 can hand another node an address inside a
// live block — and that node's later release frees a block someone else is using.
func TestWarmReservesTheWholeBlockBehindAHostAlias(t *testing.T) {
	ctx := context.Background()
	held := netip.MustParsePrefix("100.96.0.22/32")
	block := netip.MustParsePrefix("100.96.0.0/24")

	p := NewMemAliasIPAM()
	p.Warm([]netip.Prefix{held})

	for i := 0; i < 8; i++ {
		a, err := p.Allocate(ctx, 1, netip.MustParsePrefix("10.0.0.5/32"))
		if err != nil {
			t.Fatalf("allocate: %v", err)
		}
		if block.Contains(a.Addr()) {
			t.Fatalf("handed out %v, inside block %v which a host alias already holds", a, block)
		}
	}
	a, err := p.Allocate(ctx, 1, netip.MustParsePrefix("192.168.9.0/24"))
	if err != nil {
		t.Fatalf("allocate /24: %v", err)
	}
	if a == block {
		t.Fatalf("handed out %v as a whole /24 while a host alias lives in it", a)
	}
}

// Reclaimed space must be USABLE for the sizes actually asked for. A pool whose
// only free space is one big hole, with an allocator that matches on exact size,
// reports "exhausted" while sitting on most of a /11.
func TestAliasPoolSplitsALargerFreeBlock(t *testing.T) {
	ctx := context.Background()
	p := NewMemAliasIPAM()
	big, err := p.Allocate(ctx, 1, netip.MustParsePrefix("10.0.0.0/16"))
	if err != nil {
		t.Fatalf("allocate /16: %v", err)
	}
	if err := p.Release(ctx, big); err != nil {
		t.Fatalf("release: %v", err)
	}
	// The /16 is the lowest free space; a /24 request must carve it up rather
	// than skipping past it.
	a, err := p.Allocate(ctx, 1, netip.MustParsePrefix("192.168.1.0/24"))
	if err != nil {
		t.Fatalf("allocate /24 after releasing a /16: %v", err)
	}
	if !big.Contains(a.Addr()) {
		t.Fatalf("allocated %v from new space instead of splitting the free %v", a, big)
	}
}

// Split without merge is a one-way ratchet: carve a /16 into /24s, give them all
// back, and the pool can never satisfy a /16 again even though nothing is held.
func TestAliasPoolCoalescesOnRelease(t *testing.T) {
	ctx := context.Background()
	p := NewMemAliasIPAM()
	lan := netip.MustParsePrefix("192.168.1.0/24")

	var blocks []netip.Prefix
	for i := 0; i < 256; i++ {
		a, err := p.Allocate(ctx, 1, lan)
		if err != nil {
			t.Fatalf("allocate %d: %v", i, err)
		}
		blocks = append(blocks, a)
	}
	for _, a := range blocks {
		if err := p.Release(ctx, a); err != nil {
			t.Fatalf("release: %v", err)
		}
	}
	got, err := p.Allocate(ctx, 1, netip.MustParsePrefix("10.0.0.0/16"))
	if err != nil {
		t.Fatalf("a /16 must be available again after 256 /24s were returned: %v", err)
	}
	if got.Bits() != 16 {
		t.Fatalf("got %v, want a /16", got)
	}
}

// Deleting a node must give back the BLOCK its host routes came out of, not the
// /32s. DeleteNode replays node.RouteAliases, which stores the per-route alias —
// returning those verbatim would hand back 1 address and strand the other 255,
// permanently and invisibly, every time a machine with a host route is removed.
func TestDeleteNodeReturnsTheWholeAliasBlock(t *testing.T) {
	ctx := context.Background()
	c := newTestCoord()
	pool := NewMemAliasIPAM()
	c.AliasIPAM = pool
	full := pool.FreeAddrs()

	hosts := []netip.Prefix{
		netip.MustParsePrefix("192.168.1.22/32"),
		netip.MustParsePrefix("192.168.1.222/32"),
	}
	node, err := c.Register(ctx, RegisterInput{
		Meshnet: MeshnetID(1), Name: "router", NodeKey: key(1),
		AdvertisedRoutes: hosts, AliasedRoutes: hosts,
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if len(node.RouteAliases) != 2 {
		t.Fatalf("aliases = %v, want two", node.RouteAliases)
	}
	// Both host routes share one /24 block, so exactly 256 addresses left.
	if got, want := pool.FreeAddrs(), full-256; got != want {
		t.Fatalf("after allocating two host aliases free = %d, want %d (one /24)", got, want)
	}

	if err := c.DeleteNode(ctx, MeshnetID(1), node.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if got := pool.FreeAddrs(); got != full {
		t.Fatalf("after deleting the node free = %d, want the pool back to %d — %d addresses leaked",
			got, full, full-got)
	}
}

// The pool must survive being filled and drained without losing anything: an
// allocator that leaks a little per cycle is indistinguishable from a working
// one until the platform is old.
func TestAliasPoolIsLosslessOverManyCycles(t *testing.T) {
	ctx := context.Background()
	p := NewMemAliasIPAM()
	full := p.FreeAddrs()
	sizes := []string{"192.168.1.0/24", "10.9.0.0/16", "192.168.1.22/32", "172.20.5.0/25"}

	for cycle := 0; cycle < 20; cycle++ {
		var held []netip.Prefix
		for _, s := range sizes {
			a, err := p.Allocate(ctx, 1, netip.MustParsePrefix(s))
			if err != nil {
				t.Fatalf("cycle %d allocate %s: %v", cycle, s, err)
			}
			held = append(held, a)
		}
		for _, a := range held {
			if err := p.Release(ctx, a); err != nil {
				t.Fatalf("cycle %d release: %v", cycle, err)
			}
		}
		if got := p.FreeAddrs(); got != full {
			t.Fatalf("after cycle %d free = %d, want %d — %d addresses lost per round trip",
				cycle, got, full, full-got)
		}
	}
}
