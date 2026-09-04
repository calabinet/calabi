package core

import (
	"context"
	"errors"
	"net/netip"
	"sync"
)

// carrierGradeNAT is the 100.64.0.0/10 shared address space (RFC 6598) the mesh
// overlay draws stable per-node /32s from — the same range Tailscale uses, so it
// won't collide with typical RFC 1918 LANs behind a node.
var carrierGradeNAT = netip.MustParsePrefix("100.64.0.0/10")

// ErrPoolExhausted is returned when the overlay range has no free address.
var ErrPoolExhausted = errors.New("core: overlay address pool exhausted")

// MemIPAM is a simple sequential allocator over 100.64.0.0/10, held in memory.
// v0 hands out globally-unique addresses (not yet partitioned per meshnet); the
// platform build (MESH.8) will persist allocations and may segment per meshnet.
type MemIPAM struct {
	mu       sync.Mutex
	next     netip.Addr
	returned []netip.Addr // freed addresses, reused before advancing next
}

// NewMemIPAM starts allocation at 100.64.0.1 (skipping the network address).
func NewMemIPAM() *MemIPAM {
	return &MemIPAM{next: carrierGradeNAT.Addr().Next()}
}

func (p *MemIPAM) Allocate(_ context.Context, _ MeshnetID) (netip.Addr, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if n := len(p.returned); n > 0 {
		addr := p.returned[n-1]
		p.returned = p.returned[:n-1]
		return addr, nil
	}
	if !carrierGradeNAT.Contains(p.next) {
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
		if carrierGradeNAT.Contains(a) && a.Compare(p.next) >= 0 {
			p.next = a.Next()
		}
	}
}

func (p *MemIPAM) Release(_ context.Context, addr netip.Addr) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if carrierGradeNAT.Contains(addr) {
		p.returned = append(p.returned, addr)
	}
	return nil
}
