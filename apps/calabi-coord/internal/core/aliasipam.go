package core

import (
	"context"
	"encoding/binary"
	"errors"
	"math/bits"
	"net/netip"
	"sort"
	"sync"
)

// Alias allocation for overlapping subnets.
//
// A subnet router advertising 192.168.1.0/24 is unreachable from a consumer that
// is ITSELF on 192.168.1.0/24 — the destination address means two different
// machines and no routing table can tell them apart. The fix is to stop asking
// it to: the coordinator hands the consumer a UNIQUE stand-in prefix of the same
// size, and the router rewrites 1:1 on the way in. 100.96.5.222 is that site's
//.222; the consumer's own.222 is untouched.
//
// Same size, host bits preserved, is not a convenience — it is what makes the
// rewrite a stateless `iptables -j NETMAP --to <real>` instead of a table.

// ErrAliasPoolExhausted is returned when overlayAliasPool has no free block of
// the requested size.
var ErrAliasPoolExhausted = errors.New("core: subnet alias pool exhausted")

// ErrAliasUnsupportedPrefix is returned for a subnet that cannot be aliased:
// IPv6 (v0 is IPv4-only, matching the router's NETMAP rules), or one so large it
// could not fit in the alias pool even empty.
var ErrAliasUnsupportedPrefix = errors.New("core: subnet cannot be aliased")

// MemAliasIPAM hands out alias PREFIXES from overlayAliasPool, held in memory.
//
// Allocation is aligned — a /24 alias starts on a /24 boundary — because NETMAP
// maps a block onto a block, and an unaligned "prefix" is not a prefix.
//
// The whole model is the free list: a buddy allocator over the pool, split on
// demand and merged on release. It replaced a high-water mark plus a list of
// exact-size leftovers, which lost address space three separate ways:
//
//   - The allocator lives in memory and is warmed at startup from what the STORE
//     still holds. A block released BEFORE a restart is held by nobody, so it is
//     not in that set — and it sat below the high-water mark, so nothing ever
//     reached it again. Every restart burned every release since the last one,
//     permanently, out of a /11 shared by the whole platform.
//   - Leftovers only matched an exact size, so a returned /16 could not answer a
//     /24 request. The pool could report "exhausted" while sitting on most of
//     itself.
//   - And without merging, splitting was a ratchet: carve a /16 into 256 /24s,
//     hand them all back, and no /16 could ever be allocated again.
//
// Warm now rebuilds the free list as "the pool minus what is held", so a restart
// RECLAIMS rather than burns, and no allocation state needs persisting — the
// nodes are already the record of what is out.
type MemAliasIPAM struct {
	mu   sync.Mutex
	free []netip.Prefix // free, aligned blocks, sorted by address
}

// NewMemAliasIPAM starts with the whole pool free.
func NewMemAliasIPAM() *MemAliasIPAM {
	return &MemAliasIPAM{free: []netip.Prefix{overlayAliasPool}}
}

// aliasAllocUnit is the block that actually left the pool for a given alias.
//
// An alias longer than /24 is one slice of a /24 that was reserved as a unit:
// reconcileAliases reuses that block for the node's other host routes, and
// releasable() hands the whole block back when the last of them goes. Treating
// such an alias as if it occupied only its own /32 would let a second node be
// given an address INSIDE a live block — and that node's later release would
// then free a block the first one is still using.
func aliasAllocUnit(alias netip.Prefix) netip.Prefix {
	alias = alias.Masked()
	if alias.IsValid() && alias.Addr().Is4() && alias.Bits() > aliasGroupBits {
		return containingBlock(alias)
	}
	return alias
}

// Allocate returns a free alias block the same size as real. The mapping is
// positional: alias.N is real.N, so a caller that knows the LAN host is.222
// knows the alias without a lookup.
//
// meshnetID is accepted and ignored, like the node allocator's: v0 aliases are
// globally unique. Per-meshnet reuse would be denser, and would also mean two
// meshnets can hold the same alias — a property worth having only once anything
// can carry a netmap from one meshnet to another, which nothing does.
func (p *MemAliasIPAM) Allocate(_ context.Context, _ MeshnetID, real netip.Prefix) (netip.Prefix, error) {
	real = real.Masked()
	if !real.IsValid() || !real.Addr().Is4() {
		return netip.Prefix{}, ErrAliasUnsupportedPrefix
	}
	want := real.Bits()
	if want < overlayAliasPool.Bits() {
		return netip.Prefix{}, ErrAliasUnsupportedPrefix // wider than the pool itself
	}
	// Anything longer than a /24 is served out of a /24 block, so that is the
	// unit to take from the pool (allocateAlias then carves the exact prefix out
	// of it at the right offset).
	if want > aliasGroupBits {
		want = aliasGroupBits
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Best fit: the SMALLEST free block that still holds the request (the largest
	// Bits() no greater than want). First-fit would carve up the pool's big
	// contiguous runs to serve /24s and leave nothing able to answer a /16.
	best := -1
	for i, f := range p.free {
		if f.Bits() > want {
			continue // too small
		}
		if best < 0 || f.Bits() > p.free[best].Bits() {
			best = i
		}
	}
	if best < 0 {
		return netip.Prefix{}, ErrAliasPoolExhausted
	}
	blk := p.free[best]
	p.free = append(p.free[:best], p.free[best+1:]...)
	// Split down to size, keeping the lower half and returning the upper one.
	for blk.Bits() < want {
		lower, upper := halve(blk)
		p.insertFree(upper)
		blk = lower
	}
	return blk, nil
}

// Release returns an alias block to the pool.
//
// The alias is normalised to the unit that was allocated (see aliasAllocUnit),
// so a caller replaying a node's stored aliases — DeleteNode does exactly that —
// gives back the /24 a host route came out of rather than the /32, which would
// leak the other 255 addresses and leave the block charged to nobody.
//
// Blocks outside the pool are ignored rather than rejected: the caller is
// usually replaying stored state, and a foreign prefix there is stale data, not
// a programming error. Releasing something already free is a no-op — handing the
// same block to two nodes is the one outcome that must not be possible, and two
// host routes out of one /24 legitimately release the same unit twice.
func (p *MemAliasIPAM) Release(_ context.Context, alias netip.Prefix) error {
	unit := aliasAllocUnit(alias)
	if !unit.IsValid() || !unit.Addr().Is4() || !overlayAliasPool.Contains(unit.Addr()) {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, f := range p.free {
		if f.Bits() <= unit.Bits() && f.Contains(unit.Addr()) {
			return nil // already free, or inside a block that is
		}
	}
	p.insertFree(unit)
	return nil
}

// Warm rebuilds the free list as "the pool minus what is held", for a
// coordinator that reloaded its nodes from the store.
//
// It REPLACES the free list rather than adding to it: this runs once, at
// startup, on a fresh allocator, and the node store is the complete record of
// what is out. That is what makes a restart reclaim the blocks released before
// it instead of losing them — see the type comment.
func (p *MemAliasIPAM) Warm(used []netip.Prefix) {
	held := make([]netip.Prefix, 0, len(used))
	seen := map[netip.Prefix]bool{}
	for _, a := range used {
		u := aliasAllocUnit(a)
		if !u.IsValid() || !u.Addr().Is4() || !overlayAliasPool.Contains(u.Addr()) || seen[u] {
			continue
		}
		seen[u] = true
		held = append(held, u)
	}
	sort.Slice(held, func(i, j int) bool { return u32(held[i].Addr()) < u32(held[j].Addr()) })

	lo := u32(overlayAliasPool.Addr())
	hi, ok := blockEnd(lo, blockSize(overlayAliasPool.Bits()))
	if !ok {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.free = nil
	cur := lo
	for _, h := range held {
		start := u32(h.Addr())
		end, ok := blockEnd(start, blockSize(h.Bits()))
		if !ok || end < cur {
			continue // already covered by an earlier, larger held block
		}
		if start > cur {
			p.addRange(cur, start-1)
		}
		if end == ^uint32(0) {
			return
		}
		cur = end + 1
	}
	if cur <= hi {
		p.addRange(cur, hi)
	}
}

// FreeAddrs is how much of the pool is unallocated, in addresses. For reporting:
// a shared resource whose level nobody can see is one that runs out without
// warning.
func (p *MemAliasIPAM) FreeAddrs() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	var n uint64
	for _, f := range p.free {
		n += uint64(blockSize(f.Bits()))
	}
	return n
}

// addRange adds [start,end] to the free list as maximal aligned blocks. Caller
// holds the lock.
func (p *MemAliasIPAM) addRange(start, end uint32) {
	for start <= end {
		size := uint32(1) << 31
		if start != 0 {
			size = start & (^start + 1) // alignment: the lowest set bit
		}
		span := uint64(end) - uint64(start) + 1
		for uint64(size) > span {
			size >>= 1
		}
		p.insertFree(netip.PrefixFrom(addr4(start), bitsForSize(size)))
		next := uint64(start) + uint64(size)
		if next > uint64(^uint32(0)) {
			return
		}
		start = uint32(next)
	}
}

// insertFree adds blk and merges it upward with its buddy for as long as both
// halves are free. Without the merge, splitting is a one-way ratchet: a /16
// carved into /24s and fully returned could never answer a /16 again. Caller
// holds the lock.
func (p *MemAliasIPAM) insertFree(blk netip.Prefix) {
	for blk.Bits() > overlayAliasPool.Bits() {
		buddy, ok := buddyOf(blk)
		if !ok {
			break
		}
		idx := -1
		for i, f := range p.free {
			if f == buddy {
				idx = i
				break
			}
		}
		if idx < 0 {
			break
		}
		p.free = append(p.free[:idx], p.free[idx+1:]...)
		blk = parentOf(blk)
	}
	p.free = append(p.free, blk)
	sort.Slice(p.free, func(i, j int) bool { return u32(p.free[i].Addr()) < u32(p.free[j].Addr()) })
}

// halve splits a block into its two aligned halves.
func halve(b netip.Prefix) (lower, upper netip.Prefix) {
	n := b.Bits() + 1
	start := u32(b.Addr())
	return netip.PrefixFrom(addr4(start), n),
		netip.PrefixFrom(addr4(start+blockSize(n)), n)
}

// buddyOf is the sibling block blk would merge with; ok=false at the pool's own
// size, which has no sibling inside the pool.
func buddyOf(blk netip.Prefix) (netip.Prefix, bool) {
	if blk.Bits() <= overlayAliasPool.Bits() {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr4(u32(blk.Addr())^blockSize(blk.Bits())), blk.Bits()), true
}

// parentOf is the block one size up that contains blk.
func parentOf(blk netip.Prefix) netip.Prefix {
	return netip.PrefixFrom(blk.Addr(), blk.Bits()-1).Masked()
}

// bitsForSize is the prefix length covering size addresses (a power of two).
func bitsForSize(size uint32) int { return 32 - bits.TrailingZeros32(size) }

// --- IPv4 block arithmetic ---------------------------------------------------

func u32(a netip.Addr) uint32 {
	b := a.As4()
	return binary.BigEndian.Uint32(b[:])
}

func addr4(v uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}

// blockSize is how many addresses a /bits covers. bits is always in [11,32]
// here (Allocate rejects anything wider than the pool), so the shift is safe.
func blockSize(n int) uint32 { return uint32(1) << uint(32-n) }

// blockEnd is the last address of the block starting at start, or ok=false if
// the block would run past the end of the address space.
func blockEnd(start, size uint32) (uint32, bool) {
	if start > ^uint32(0)-(size-1) {
		return 0, false
	}
	return start + size - 1, true
}
