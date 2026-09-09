package core

import (
	"context"
	"errors"
	"net/netip"
	"sync"
)

// carrierGradeNAT is the 100.64.0.0/10 shared address space (RFC 6598) the mesh
// overlay lives in — the same range Tailscale uses, so it won't collide with
// typical RFC 1918 LANs behind a node. The client routes this WHOLE prefix into
// the tun (mesh.meshOverlayCIDR), which is what lets everything below be handed
// to a consumer with no consumer-side change at all.
var carrierGradeNAT = netip.MustParsePrefix("100.64.0.0/10")

// The overlay is split in two, and the split is load-bearing.
//
// Node /32s come from the lower half. Subnet ALIASES — whole prefixes standing
// in for a subnet router's real LAN, so two sites that both use 192.168.1.0/24
// can reach each other — come from
// the upper half. They MUST NOT be able to collide: an alias that lands on a
// node's overlay address would route that node's own traffic into somebody's
// LAN. Two allocators sharing one range and staying out of each other's way by
// convention is exactly the arrangement that holds until it doesn't, so the
// ranges are disjoint by construction and TestOverlayPoolsCannotOverlap says so.
//
// The plan proposed carving aliases out of "the meshnet's own overlay slice".
// There is no such slice: MemIPAM hands out globally-unique addresses across the
// whole /10 (see its comment). Reserving half is the honest version of that idea
// against the allocator that actually exists.
var (
	overlayNodePool  = netip.MustParsePrefix("100.64.0.0/11") // 100.64.0.0 – 100.95.255.255
	overlayAliasPool = netip.MustParsePrefix("100.96.0.0/11") // 100.96.0.0 – 100.127.255.255
)

// ErrPoolExhausted is returned when the overlay range has no free address.
var ErrPoolExhausted = errors.New("core: overlay address pool exhausted")

// MemIPAM is a simple sequential allocator over overlayNodePool, held in memory.
// v0 hands out globally-unique addresses (not yet partitioned per meshnet); the
// platform build (MESH.8) will persist allocations and may segment per meshnet.
//
// Bounded to the node half of the overlay rather than the whole /10: see the
// pool comment above. Every address ever handed out lives in 100.64.0.0/11
// already — allocation starts at 100.64.0.1 and walks up — so narrowing the
// bound retires no existing address.
type MemIPAM struct {
	mu       sync.Mutex
	next     netip.Addr
	returned []netip.Addr // freed addresses, reused before advancing next
}

// NewMemIPAM starts allocation at 100.64.0.1 (skipping the network address).
func NewMemIPAM() *MemIPAM {
	return &MemIPAM{next: overlayNodePool.Addr().Next()}
}

func (p *MemIPAM) Allocate(_ context.Context, _ MeshnetID) (netip.Addr, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if n := len(p.returned); n > 0 {
		addr := p.returned[n-1]
		p.returned = p.returned[:n-1]
		return addr, nil
	}
	if !overlayNodePool.Contains(p.next) {
		return netip.Addr{}, ErrPoolExhausted
	}
	addr := p.next
	p.next = p.next.Next()
	return addr, nil
}

// Warm advances the allocator past the highest address already in use, so a
// coordinator that reloaded its nodes from a persistent store (MESH.8c) never
// hands a NEW node an address a persisted node already holds. Existing nodes
// keep their stored overlay via idempotent re-enrollment (FindByKey), so only
// fresh allocations need protecting. Gaps below the max aren't reclaimed — the
// /10 pool is vast; exact-set reservation waits until IPAM itself is persisted.
func (p *MemIPAM) Warm(used []netip.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, a := range used {
		if overlayNodePool.Contains(a) && a.Compare(p.next) >= 0 {
			p.next = a.Next()
		}
	}
}

func (p *MemIPAM) Release(_ context.Context, addr netip.Addr) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if overlayNodePool.Contains(addr) {
		p.returned = append(p.returned, addr)
	}
	return nil
}
