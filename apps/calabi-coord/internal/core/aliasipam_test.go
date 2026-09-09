package core

import (
	"context"
	"net/netip"
	"testing"
)

func pfx(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return p
}

// The one property the whole scheme rests on: a node's overlay address and a
// subnet alias can never be the same address. If they could, an alias would
// eventually land on some node's /32 and route that node's own traffic into a
// stranger's LAN — silently, and only for whoever drew the unlucky address.
func TestOverlayPoolsCannotOverlap(t *testing.T) {
	if overlayNodePool.Overlaps(overlayAliasPool) {
		t.Fatalf("node pool %s overlaps alias pool %s", overlayNodePool, overlayAliasPool)
	}
	for _, p := range []netip.Prefix{overlayNodePool, overlayAliasPool} {
		if !carrierGradeNAT.Contains(p.Addr()) {
			t.Errorf("%s starts outside the overlay range %s", p, carrierGradeNAT)
		}
		end, _ := blockEnd(u32(p.Addr()), blockSize(p.Bits()))
		if !carrierGradeNAT.Contains(addr4(end)) {
			t.Errorf("%s ends outside the overlay range %s", p, carrierGradeNAT)
		}
	}
	// Together they must cover the whole /10: the client routes 100.64.0.0/10
	// into the tun, and an address in neither pool would be routed there by every
	// consumer while nothing can ever be reached at it.
	if u32(overlayAliasPool.Addr()) != u32(overlayNodePool.Addr())+blockSize(overlayNodePool.Bits()) {
		t.Errorf("pools are not adjacent: %s then %s", overlayNodePool, overlayAliasPool)
	}
}

// Allocation is by BLOCK: same size as the real subnet, aligned, so the router's
// stateless NETMAP rewrite is possible at all.
func TestMemAliasIPAMAllocatesAlignedSameSizeBlocks(t *testing.T) {
	p := NewMemAliasIPAM()
	ctx := context.Background()

	for _, real := range []string{"192.168.1.0/24", "10.0.0.0/16", "172.16.4.0/22"} {
		r := pfx(t, real)
		a, err := p.Allocate(ctx, MeshnetID(1), r)
		if err != nil {
			t.Fatalf("allocate %s: %v", real, err)
		}
		if a.Bits() != r.Bits() {
			t.Errorf("%s -> %s: size %d, want %d", real, a, a.Bits(), r.Bits())
		}
		if a != a.Masked() {
			t.Errorf("%s -> %s is not aligned on its own boundary", real, a)
		}
		if !overlayAliasPool.Contains(a.Addr()) {
			t.Errorf("%s -> %s is outside the alias pool %s", real, a, overlayAliasPool)
		}
		if overlayNodePool.Contains(a.Addr()) {
			t.Errorf("%s -> %s landed in the NODE pool", real, a)
		}
	}
}

// alias.N is real.N. This is what lets a user who knows the NAS is.222 reach it
// at <alias prefix>.222 without consulting a table, and what NETMAP implements.
func TestMemAliasIPAMHostBitsArePositional(t *testing.T) {
	p := NewMemAliasIPAM()
	real := pfx(t, "192.168.1.0/24")
	alias, err := p.Allocate(context.Background(), MeshnetID(1), real)
	if err != nil {
		t.Fatal(err)
	}
	host := u32(netip.MustParseAddr("192.168.1.222")) - u32(real.Addr())
	got := addr4(u32(alias.Addr()) + host)
	if !alias.Contains(got) {
		t.Fatalf("%s is not inside the alias block %s", got, alias)
	}
	if got.As4()[3] != 222 {
		t.Errorf("host byte moved: %s (want a .222 inside %s)", got, alias)
	}
}

// Two allocations never overlap, and a block is never handed out twice.
func TestMemAliasIPAMBlocksNeverOverlap(t *testing.T) {
	p := NewMemAliasIPAM()
	ctx := context.Background()
	var got []netip.Prefix
	for _, real := range []string{"192.168.1.0/24", "192.168.2.0/24", "10.1.0.0/16", "192.168.3.0/24"} {
		a, err := p.Allocate(ctx, MeshnetID(1), pfx(t, real))
		if err != nil {
			t.Fatalf("allocate %s: %v", real, err)
		}
		for _, prev := range got {
			if prev.Overlaps(a) {
				t.Fatalf("%s overlaps previously allocated %s", a, prev)
			}
		}
		got = append(got, a)
	}
}

func TestMemAliasIPAMReusesReleasedBlocks(t *testing.T) {
	p := NewMemAliasIPAM()
	ctx := context.Background()
	real := pfx(t, "192.168.1.0/24")

	first, err := p.Allocate(ctx, MeshnetID(1), real)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Release(ctx, first); err != nil {
		t.Fatal(err)
	}
	// Releasing twice must not make the same block allocatable twice.
	if err := p.Release(ctx, first); err != nil {
		t.Fatal(err)
	}
	again, err := p.Allocate(ctx, MeshnetID(1), real)
	if err != nil {
		t.Fatal(err)
	}
	if again != first {
		t.Errorf("released block not reused: got %s, want %s", again, first)
	}
	next, err := p.Allocate(ctx, MeshnetID(1), real)
	if err != nil {
		t.Fatal(err)
	}
	if next == first {
		t.Errorf("block %s handed out twice", next)
	}
}

// A coordinator that reloaded persisted nodes must not re-hand a block one of
// them already holds.
func TestMemAliasIPAMWarmAvoidsPersistedCollision(t *testing.T) {
	p := NewMemAliasIPAM()
	held := pfx(t, "100.96.0.0/16")
	p.Warm([]netip.Prefix{held, pfx(t, "192.168.1.0/24") /* foreign: ignored */})

	a, err := p.Allocate(context.Background(), MeshnetID(1), pfx(t, "10.0.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if held.Overlaps(a) {
		t.Fatalf("handed out %s, which overlaps the persisted %s", a, held)
	}
}

func TestMemAliasIPAMRejectsWhatItCannotAlias(t *testing.T) {
	p := NewMemAliasIPAM()
	ctx := context.Background()
	for _, real := range []string{
		"fd00::/64",   // v0 is IPv4-only, like the router's NETMAP rules
		"10.0.0.0/8",  // wider than the /11 pool: could never fit
		"128.0.0.0/1", // absurd, same reason
	} {
		if _, err := p.Allocate(ctx, MeshnetID(1), pfx(t, real)); err != ErrAliasUnsupportedPrefix {
			t.Errorf("allocate %s: err=%v, want ErrAliasUnsupportedPrefix", real, err)
		}
	}
}

func TestMemAliasIPAMExhaustion(t *testing.T) {
	p := NewMemAliasIPAM()
	ctx := context.Background()
	// One /11 exactly fills the pool.
	if _, err := p.Allocate(ctx, MeshnetID(1), pfx(t, "10.0.0.0/11")); err != nil {
		t.Fatalf("first /11: %v", err)
	}
	if _, err := p.Allocate(ctx, MeshnetID(1), pfx(t, "10.32.0.0/24")); err != ErrAliasPoolExhausted {
		t.Errorf("after filling the pool: err=%v, want ErrAliasPoolExhausted", err)
	}
}

// The node allocator and the alias allocator, run side by side, must never meet.
func TestNodeAndAliasAllocatorsStayDisjoint(t *testing.T) {
	ctx := context.Background()
	nodes := NewMemIPAM()
	aliases := NewMemAliasIPAM()

	var addrs []netip.Addr
	for i := 0; i < 500; i++ {
		a, err := nodes.Allocate(ctx, MeshnetID(1))
		if err != nil {
			t.Fatalf("node %d: %v", i, err)
		}
		addrs = append(addrs, a)
	}
	for i := 0; i < 50; i++ {
		block, err := aliases.Allocate(ctx, MeshnetID(1), pfx(t, "192.168.1.0/24"))
		if err != nil {
			t.Fatalf("alias %d: %v", i, err)
		}
		for _, a := range addrs {
			if block.Contains(a) {
				t.Fatalf("alias block %s swallowed node overlay %s", block, a)
			}
		}
	}
}
