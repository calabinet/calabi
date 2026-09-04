package core

import (
	"context"
	"errors"
	"testing"
)

// Deleting a device removes it from every peer's netmap and takes its declared
// services with it. The services matter most: a service name is an ACL
// SELECTOR, so an orphaned row would keep granting access to a device that no
// longer exists.
func TestDeleteNodeRemovesServicesAndPeers(t *testing.T) {
	c := newTestCoord()
	c.Services = NewMemServiceStore()
	ctx := context.Background()

	a, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "a", NodeKey: key(1)})
	if err != nil {
		t.Fatalf("register a: %v", err)
	}
	b, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "b", NodeKey: key(2)})
	if err != nil {
		t.Fatalf("register b: %v", err)
	}
	if _, err := c.Services.CreateService(ctx, Service{Meshnet: 1, NodeID: a.ID, Name: "db", Proto: "tcp", Port: 5432}); err != nil {
		t.Fatalf("create service on a: %v", err)
	}
	if _, err := c.Services.CreateService(ctx, Service{Meshnet: 1, NodeID: b.ID, Name: "web", Proto: "tcp", Port: 80}); err != nil {
		t.Fatalf("create service on b: %v", err)
	}

	if err := c.DeleteNode(ctx, 1, a.ID); err != nil {
		t.Fatalf("delete a: %v", err)
	}

	if _, err := c.Nodes.Get(ctx, a.ID); !errors.Is(err, ErrNodeNotFound) {
		t.Errorf("node still readable after delete: err = %v", err)
	}
	svcs, err := c.Services.ListServices(ctx, 1)
	if err != nil {
		t.Fatalf("list services: %v", err)
	}
	if len(svcs) != 1 || svcs[0].NodeID != b.ID {
		t.Fatalf("services after delete = %+v, want only b's", svcs)
	}
	// b must no longer see a.
	nm, err := c.NetMapFor(ctx, b.ID)
	if err != nil {
		t.Fatalf("netmap for b: %v", err)
	}
	for _, p := range nm.Peers {
		if p.ID == a.ID {
			t.Fatalf("deleted node still in b's netmap")
		}
	}
}

// Same cross-tenant guard every other node mutation has: an id belonging to
// another meshnet must 404, not delete. Without it a manager of org A could
// delete org B's devices by guessing ids.
func TestDeleteNodeRefusesOtherMeshnet(t *testing.T) {
	c := newTestCoord()
	ctx := context.Background()
	other, err := c.Register(ctx, RegisterInput{Meshnet: 2, Name: "theirs", NodeKey: key(9)})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	if err := c.DeleteNode(ctx, 1, other.ID); !errors.Is(err, ErrNodeNotFound) {
		t.Fatalf("cross-meshnet delete err = %v, want ErrNodeNotFound", err)
	}
	if _, err := c.Nodes.Get(ctx, other.ID); err != nil {
		t.Fatalf("other org's node was deleted: %v", err)
	}
}

// The overlay address goes back to the pool. Order matters — the node row is
// removed BEFORE the release, so the address can never be handed to a new node
// while the old one still answers to it.
func TestDeleteNodeReleasesOverlay(t *testing.T) {
	c := newTestCoord()
	ctx := context.Background()
	a, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "a", NodeKey: key(1)})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	freed := a.Overlay

	if err := c.DeleteNode(ctx, 1, a.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	next, err := c.IPAM.Allocate(ctx, 1)
	if err != nil {
		t.Fatalf("allocate after delete: %v", err)
	}
	if next != freed {
		t.Errorf("released %v was not reused (got %v)", freed, next)
	}
}

// Deleting is not a kill switch: a daemon that is still running re-enrolls and
// comes back as a NEW device. Pinning that here so nobody "fixes" the console
// copy into claiming otherwise.
func TestDeleteNodeThenReregisterIsANewDevice(t *testing.T) {
	c := newTestCoord()
	ctx := context.Background()
	a, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "a", NodeKey: key(1)})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := c.DeleteNode(ctx, 1, a.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	again, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "a", NodeKey: key(1)})
	if err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if again.ID == a.ID {
		t.Errorf("re-registration reused the deleted id %d", a.ID)
	}
}

func TestDeleteNodeUnknownID(t *testing.T) {
	c := newTestCoord()
	if err := c.DeleteNode(context.Background(), 1, 4242); !errors.Is(err, ErrNodeNotFound) {
		t.Fatalf("err = %v, want ErrNodeNotFound", err)
	}
}
