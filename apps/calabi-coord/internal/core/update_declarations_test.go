package core

import (
	"context"
	"errors"
	"testing"
)

// A service edit changes what a node OFFERS, not where anything is. Before this
// path existed the only way to tell the coordinator was to register again, which
// on the client side meant tearing down WireGuard and re-punching every path.
func TestUpdateDeclarations_RecordsWithoutTouchingIdentity(t *testing.T) {
	c, ctx := serviceCoord(t)

	node, err := c.Register(ctx, RegisterInput{
		Meshnet: 1, Name: "router", NodeKey: key(1), DeviceFingerprint: "fp_abc",
		DeclaredServices: []Service{{Name: "db", Proto: "tcp", Port: 5432}},
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	got, err := c.UpdateDeclarations(ctx, UpdateDeclarationsInput{
		Meshnet: 1, NodeKey: key(1),
		DeclaredServices: []Service{
			{Name: "db", Proto: "tcp", Port: 5432},
			{Name: "web", Proto: "tcp", Port: 8080},
		},
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	// Same node: no re-allocation, no churn of anything a peer depends on.
	if got.ID != node.ID {
		t.Fatalf("node id changed %d → %d", node.ID, got.ID)
	}
	if got.Overlay != node.Overlay {
		t.Fatalf("overlay changed %s → %s", node.Overlay, got.Overlay)
	}
	// An empty fingerprint means "no change", never "clear it" — the node reports
	// "" both when it has no registration yet and when its config won't read.
	if got.DeviceFingerprint != "fp_abc" {
		t.Fatalf("fingerprint = %q, want it left alone", got.DeviceFingerprint)
	}

	if _, ok := svcNamed(t, c, 1, node.ID, "db"); !ok {
		t.Error("the pre-existing declaration was dropped by the update")
	}
	if _, ok := svcNamed(t, c, 1, node.ID, "web"); !ok {
		t.Error("the new declaration was not recorded")
	}
}

// The fingerprint is the other declaration that only travelled at registration.
// Reporting one mid-session must land without a re-enrollment.
func TestUpdateDeclarations_AppliesANewFingerprint(t *testing.T) {
	c := newTestCoord()
	ctx := context.Background()
	if _, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "n", NodeKey: key(1)}); err != nil {
		t.Fatal(err)
	}
	got, err := c.UpdateDeclarations(ctx, UpdateDeclarationsInput{
		Meshnet: 1, NodeKey: key(1), DeviceFingerprint: "fp_new",
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if got.DeviceFingerprint != "fp_new" {
		t.Fatalf("fingerprint = %q, want fp_new", got.DeviceFingerprint)
	}
}

// The two refusals. Both matter: a node that isn't enrolled must be told so (the
// client then enrolls instead of silently succeeding at nothing), and a node an
// admin disabled must not be able to keep editing what the mesh knows about it
// through its own reconnect loop.
func TestUpdateDeclarations_Refusals(t *testing.T) {
	c := newTestCoord()
	ctx := context.Background()
	if _, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "n", NodeKey: key(1)}); err != nil {
		t.Fatal(err)
	}

	// Another meshnet's key: not enrolled HERE.
	if _, err := c.UpdateDeclarations(ctx, UpdateDeclarationsInput{Meshnet: 2, NodeKey: key(1)}); !errors.Is(err, ErrNodeNotFound) {
		t.Fatalf("cross-meshnet err = %v, want ErrNodeNotFound", err)
	}
	// A key nobody enrolled.
	if _, err := c.UpdateDeclarations(ctx, UpdateDeclarationsInput{Meshnet: 1, NodeKey: key(9)}); !errors.Is(err, ErrNodeNotFound) {
		t.Fatalf("unknown-key err = %v, want ErrNodeNotFound", err)
	}

	n, err := c.Nodes.FindByKey(ctx, 1, key(1))
	if err != nil {
		t.Fatal(err)
	}
	n.Disabled = true
	if _, err := c.Nodes.Upsert(ctx, n); err != nil {
		t.Fatal(err)
	}
	if _, err := c.UpdateDeclarations(ctx, UpdateDeclarationsInput{Meshnet: 1, NodeKey: key(1)}); !errors.Is(err, ErrNodeDisabled) {
		t.Fatalf("disabled err = %v, want ErrNodeDisabled", err)
	}
}
