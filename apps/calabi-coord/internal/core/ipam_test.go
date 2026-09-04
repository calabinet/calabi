package core

import (
	"context"
	"net/netip"
	"testing"
)

// Warm must push new allocations past any address already in use (persisted
// nodes reloaded from the DB), so a fresh node never collides with a live one.
func TestMemIPAMWarmAvoidsPersistedCollision(t *testing.T) {
	p := NewMemIPAM()
	ctx := context.Background()
	// Simulate a restart: nodes.1 and.2 already exist in the store.
	p.Warm([]netip.Addr{netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("100.64.0.2")})
	got, err := p.Allocate(ctx, 1)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if got.String() != "100.64.0.3" {
		t.Fatalf("post-warm allocate = %s, want 100.64.0.3 (no collision with .1/.2)", got)
	}
}
