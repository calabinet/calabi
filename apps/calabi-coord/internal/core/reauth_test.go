package core

import (
	"context"
	"errors"
	"testing"
)

// A re-registration by proof alone only ever finds a node. If the node was
// deleted after the RPC layer looked it up, creating it here would undo the
// delete with no auth key at all.
func TestReauthNeverCreatesANode(t *testing.T) {
	c := newTestCoord()
	ctx := context.Background()
	_, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "ghost", NodeKey: key(1), Reauth: true})
	if !errors.Is(err, ErrNodeNotFound) {
		t.Fatalf("err = %v, want ErrNodeNotFound", err)
	}
	if nodes, _ := c.Nodes.ListMeshnet(ctx, 1); len(nodes) != 0 {
		t.Fatalf("a node was created: %+v", nodes)
	}
}

// An enrollment with a key records who enrolled and clears a sign-out; one by
// proof alone keeps the tags and owner the key gave, whatever the input says,
// and is refused once the device signed out.
func TestReauthKeepsWhatTheKeyDecided(t *testing.T) {
	c := newTestCoord()
	ctx := context.Background()
	n, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "laptop", NodeKey: key(1),
		Tags: []string{"tag:laptop"}, OwnerUserID: 11, EnrolledBy: "user:11"})
	if err != nil {
		t.Fatal(err)
	}
	if n.EnrolledBy != "user:11" {
		t.Fatalf("EnrolledBy = %q", n.EnrolledBy)
	}

	again, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "laptop", NodeKey: key(1),
		Tags: nil, OwnerUserID: 0, EnrolledBy: "someone-else", Reauth: true})
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != n.ID || again.OwnerUserID != 11 || again.EnrolledBy != "user:11" ||
		len(again.Tags) != 1 || again.Tags[0] != "tag:laptop" {
		t.Fatalf("reauth rewrote the node: id=%d owner=%d enrolled_by=%q tags=%v", again.ID, again.OwnerUserID, again.EnrolledBy, again.Tags)
	}

	if err := c.SignOut(ctx, n.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "laptop", NodeKey: key(1), Reauth: true}); !errors.Is(err, ErrNodeSignedOut) {
		t.Fatalf("reauth after sign-out: err = %v, want ErrNodeSignedOut", err)
	}
	back, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "laptop", NodeKey: key(1),
		Tags: []string{"tag:laptop"}, OwnerUserID: 11, EnrolledBy: "user:11"})
	if err != nil || back.ID != n.ID || back.SignedOut {
		t.Fatalf("enrolling with a key after sign-out: %v, id=%d signed_out=%v", err, back.ID, back.SignedOut)
	}
}
