package store

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open("") // sqlite in-memory via the real dialer
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func key(b byte) (k meshproto.NodeKey) {
	for i := range k {
		k[i] = b
	}
	return k
}

// Exercises the full core.NodeStore contract against the DB adapter: insert
// (ID assigned) → Get / FindByKey roundtrip (all fields survive) → ListMeshnet
// tenant isolation → UpdateEndpoints → update-in-place, plus not-found paths.
func TestStoreRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	in := &core.Node{
		Meshnet:          1,
		Name:             "node-a",
		NodeKey:          key(1),
		Overlay:          netip.MustParseAddr("100.64.0.1"),
		DERPHome:         "lax",
		AdvertisedRoutes: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		Tags:             []string{"tag:eng"},
	}
	saved, err := s.Upsert(ctx, in)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if saved.ID == 0 {
		t.Fatal("insert did not assign an ID")
	}

	got, err := s.Get(ctx, saved.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "node-a" || got.Overlay.String() != "100.64.0.1" || got.DERPHome != "lax" {
		t.Fatalf("scalar fields wrong: %+v", got)
	}
	if len(got.AdvertisedRoutes) != 1 || got.AdvertisedRoutes[0].String() != "192.168.1.0/24" {
		t.Fatalf("advertised routes not preserved: %v", got.AdvertisedRoutes)
	}
	if len(got.Tags) != 1 || got.Tags[0] != "tag:eng" {
		t.Fatalf("tags not preserved: %v", got.Tags)
	}

	// FindByKey drives idempotent re-enrollment.
	byKey, err := s.FindByKey(ctx, 1, key(1))
	if err != nil || byKey.ID != saved.ID {
		t.Fatalf("FindByKey = %+v, %v; want id %d", byKey, err, saved.ID)
	}

	// A second node in another meshnet is isolated.
	if _, err := s.Upsert(ctx, &core.Node{Meshnet: 2, Name: "x", NodeKey: key(2), Overlay: netip.MustParseAddr("100.64.0.1")}); err != nil {
		t.Fatalf("insert meshnet 2: %v", err)
	}
	list1, _ := s.ListMeshnet(ctx, 1)
	if len(list1) != 1 || list1[0].Name != "node-a" {
		t.Fatalf("meshnet 1 list = %+v, want just node-a", list1)
	}

	// UpdateEndpoints persists.
	if err := s.UpdateEndpoints(ctx, saved.ID, []netip.AddrPort{netip.MustParseAddrPort("203.0.113.5:41641")}); err != nil {
		t.Fatalf("update endpoints: %v", err)
	}
	got, _ = s.Get(ctx, saved.ID)
	if len(got.Endpoints) != 1 || got.Endpoints[0].String() != "203.0.113.5:41641" {
		t.Fatalf("endpoints not persisted: %v", got.Endpoints)
	}

	// Update in place (ID != 0) refreshes mutable fields, keeps the id.
	got.Name = "renamed"
	up, err := s.Upsert(ctx, got)
	if err != nil || up.ID != saved.ID || up.Name != "renamed" {
		t.Fatalf("update-in-place = %+v, %v", up, err)
	}

	// Not-found paths.
	if _, err := s.Get(ctx, 9999); !errors.Is(err, core.ErrNodeNotFound) {
		t.Fatalf("Get(absent) = %v, want ErrNodeNotFound", err)
	}
	if _, err := s.FindByKey(ctx, 1, key(9)); !errors.Is(err, core.ErrNodeNotFound) {
		t.Fatalf("FindByKey(absent) = %v, want ErrNodeNotFound", err)
	}

	// AllOverlays feeds IPAM warm-up: both persisted overlays (meshnets 1 & 2).
	ov, err := s.AllOverlays(ctx)
	if err != nil || len(ov) != 2 {
		t.Fatalf("AllOverlays = %v, %v; want 2", ov, err)
	}

	// SetDisabled persists the kill switch (MESH.8b) and survives a re-read.
	if err := s.SetDisabled(ctx, saved.ID, true); err != nil {
		t.Fatalf("set disabled: %v", err)
	}
	got, _ = s.Get(ctx, saved.ID)
	if !got.Disabled {
		t.Fatalf("disabled not persisted")
	}
	if err := s.SetDisabled(ctx, 9999, true); !errors.Is(err, core.ErrNodeNotFound) {
		t.Fatalf("SetDisabled(absent) = %v, want ErrNodeNotFound", err)
	}
}

// TestACLStoreRoundTrip exercises the per-meshnet ACL doc persistence
// (MESH.8e-2): absent → (zero,false); Set → Get returns it; overwrite replaces;
// meshnets are isolated.
func TestACLStoreRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Absent doc → not found, no error.
	if _, ok, err := s.GetACL(ctx, 1); err != nil || ok {
		t.Fatalf("absent GetACL = (ok=%v, err=%v), want (false, nil)", ok, err)
	}

	doc := core.ACLPolicy{
		Groups: map[string][]string{"group:ops": {"tag:server"}},
		ACLs:   []core.ACLRule{{Action: "accept", Src: []string{"tag:laptop"}, Dst: []string{"group:ops"}}},
	}
	if err := s.SetACL(ctx, 1, doc); err != nil {
		t.Fatalf("SetACL: %v", err)
	}
	got, ok, err := s.GetACL(ctx, 1)
	if err != nil || !ok {
		t.Fatalf("GetACL after set = (ok=%v, err=%v)", ok, err)
	}
	if len(got.ACLs) != 1 || got.ACLs[0].Src[0] != "tag:laptop" || got.Groups["group:ops"][0] != "tag:server" {
		t.Fatalf("round-tripped doc mismatch: %+v", got)
	}

	// Overwrite replaces (still one row per meshnet).
	if err := s.SetACL(ctx, 1, core.ACLPolicy{ACLs: []core.ACLRule{{Action: "accept", Src: []string{"*"}, Dst: []string{"*"}}}}); err != nil {
		t.Fatalf("SetACL overwrite: %v", err)
	}
	got, _, _ = s.GetACL(ctx, 1)
	if len(got.ACLs) != 1 || got.ACLs[0].Src[0] != "*" || len(got.Groups) != 0 {
		t.Fatalf("overwrite mismatch: %+v", got)
	}

	// Meshnet 2 is unaffected.
	if _, ok, _ := s.GetACL(ctx, 2); ok {
		t.Fatal("meshnet 2 must have no doc")
	}
}
