package store

import (
	"context"
	"net/netip"
	"testing"

	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
)

// The bug this pins: Upsert's UPDATE branch didn't write device_fingerprint, so
// a node created before it ever had one could NEVER acquire it. The client
// reported it on every re-enrolment, core.Register merged it into the row, and
// this layer dropped it — silently, because Upsert returns the row it just
// wrote, which looked correct to everyone above.
//
// It survived because the core tests run against MemNodeStore, which persists
// whole structs and therefore cannot see a missing column in the SQL adapter.
func TestUpsertUpdatePersistsDeviceFingerprint(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Created with none — exactly how a node enrols before its daemon has a
	// Publish-side device registration.
	created, err := s.Upsert(ctx, &core.Node{
		Meshnet: 1, Name: "n", NodeKey: key(1),
		Overlay: netip.MustParseAddr("100.64.0.1"),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.DeviceFingerprint != "" {
		t.Fatalf("fresh node fingerprint = %q, want empty", created.DeviceFingerprint)
	}

	created.DeviceFingerprint = "fp_abc"
	if _, err := s.Upsert(ctx, created); err != nil {
		t.Fatalf("update: %v", err)
	}

	// Re-READ rather than trusting Upsert's return value — the whole failure
	// mode was a write that never happened behind a plausible-looking return.
	got, err := s.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.DeviceFingerprint != "fp_abc" {
		t.Fatalf("device_fingerprint = %q after update, want fp_abc", got.DeviceFingerprint)
	}
	// FindByKey is the path core.Register/UpdateDeclarations actually use.
	byKey, err := s.FindByKey(ctx, 1, key(1))
	if err != nil {
		t.Fatalf("find by key: %v", err)
	}
	if byKey.DeviceFingerprint != "fp_abc" {
		t.Fatalf("FindByKey fingerprint = %q, want fp_abc", byKey.DeviceFingerprint)
	}
}

// The other side of the same line: an enrolling node must not be able to undo an
// admin's decisions. Those three fields have their own setters and are
// deliberately absent from Upsert's UPDATE.
func TestUpsertUpdateLeavesAdminDecisionsAlone(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	n, err := s.Upsert(ctx, &core.Node{
		Meshnet: 1, Name: "n", NodeKey: key(1),
		Overlay: netip.MustParseAddr("100.64.0.1"),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.SetDisabled(ctx, n.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := s.SetApproved(ctx, n.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := s.SetTags(ctx, n.ID, []string{"tag:prod"}); err != nil {
		t.Fatal(err)
	}

	// A re-enrolment carrying the zero values for all three.
	n.Disabled, n.Approved, n.TagsPinned, n.Tags = false, false, false, nil
	n.DeviceFingerprint = "fp_abc"
	if _, err := s.Upsert(ctx, n); err != nil {
		t.Fatalf("update: %v", err)
	}

	got, err := s.Get(ctx, n.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Disabled {
		t.Error("re-enrolment cleared the admin kill switch")
	}
	if !got.Approved {
		t.Error("re-enrolment cleared the admin approval")
	}
	if !got.TagsPinned {
		t.Error("re-enrolment cleared the admin tag pin")
	}
	// ...while the node-reported field it DOES own went through.
	if got.DeviceFingerprint != "fp_abc" {
		t.Errorf("device_fingerprint = %q, want fp_abc", got.DeviceFingerprint)
	}
}
