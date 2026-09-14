// node_block_incoming_test.go — the shields switch a node REPORTS, and the two
// rules that make the report trustworthy.
//
// Node.BlockIncoming exists so the console can tell a machine that answers
// nobody from a healthy one. Enforcement is entirely local to the node, so
// nothing here changes what traffic flows — which is exactly why the value has
// to be honest: it is the only signal an admin has.
//
// It is a *bool and not a bool because there are three states. "false" and "the
// daemon never said" look identical once you flatten them, and flattening turns
// every un-upgraded machine in the fleet into a positive claim that it accepts
// connections.
//
// RUN: go test./apps/calabi-coord/internal/core/ -run TestNodeBlockIncoming -v
package core

import (
	"context"
	"testing"
)

func boolPtr(v bool) *bool { return &v }

func TestNodeBlockIncomingStartsUnknownAndSurvivesASilentDaemon(t *testing.T) {
	c := newTestCoord()
	ctx := context.Background()

	// A daemon too old to know the field says nothing.
	n, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "box", NodeKey: key(1)})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if n.BlockIncoming != nil {
		t.Fatalf("a node that never reported must be UNKNOWN, got %v", *n.BlockIncoming)
	}

	// It upgrades and turns the switch on.
	n, err = c.Register(ctx, RegisterInput{Meshnet: 1, Name: "box", NodeKey: key(1), BlockIncoming: boolPtr(true)})
	if err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if n.BlockIncoming == nil || !*n.BlockIncoming {
		t.Fatalf("reported shields were not stored: %v", n.BlockIncoming)
	}

	// Now it is downgraded, or a build predating the field re-registers. Silence
	// is not a retraction.
	n, err = c.Register(ctx, RegisterInput{Meshnet: 1, Name: "box", NodeKey: key(1)})
	if err != nil {
		t.Fatalf("re-register silent: %v", err)
	}
	if n.BlockIncoming == nil || !*n.BlockIncoming {
		t.Fatalf("a silent re-registration cleared the stored switch: %v", n.BlockIncoming)
	}
	// Same on the declaration path, which is the one an in-place upgrade takes.
	n, err = c.UpdateDeclarations(ctx, UpdateDeclarationsInput{Meshnet: 1, NodeKey: key(1)})
	if err != nil {
		t.Fatalf("update declarations: %v", err)
	}
	if n.BlockIncoming == nil || !*n.BlockIncoming {
		t.Fatalf("a silent declaration push cleared the switch: %v", n.BlockIncoming)
	}
}

// Turning the switch OFF has to travel. It is a reported false, not silence, and
// the merge must tell them apart — otherwise a machine could go shielded and
// never come back in the console, which is the more alarming of the two errors.
func TestNodeBlockIncomingOffIsReportedNotSilence(t *testing.T) {
	c := newTestCoord()
	ctx := context.Background()

	if _, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "box", NodeKey: key(1), BlockIncoming: boolPtr(true)}); err != nil {
		t.Fatalf("register: %v", err)
	}
	n, err := c.UpdateDeclarations(ctx, UpdateDeclarationsInput{Meshnet: 1, NodeKey: key(1), BlockIncoming: boolPtr(false)})
	if err != nil {
		t.Fatalf("update declarations: %v", err)
	}
	if n.BlockIncoming == nil {
		t.Fatal("an explicit false was read as silence and left the value unknown")
	}
	if *n.BlockIncoming {
		t.Fatal("the switch was reported off and stayed on")
	}

	// And the registration path agrees with the declaration path.
	n, err = c.Register(ctx, RegisterInput{Meshnet: 1, Name: "box", NodeKey: key(1), BlockIncoming: boolPtr(true)})
	if err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if n.BlockIncoming == nil || !*n.BlockIncoming {
		t.Fatalf("re-registration did not apply a reported true: %v", n.BlockIncoming)
	}
}

// A fresh node that reports the switch on the very first registration keeps it:
// the create path and the merge path have to agree, and only one of them was
// exercised above.
func TestNodeBlockIncomingOnFirstRegistration(t *testing.T) {
	c := newTestCoord()
	n, err := c.Register(context.Background(), RegisterInput{
		Meshnet: 1, Name: "shy", NodeKey: key(2), BlockIncoming: boolPtr(true),
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if n.BlockIncoming == nil || !*n.BlockIncoming {
		t.Fatalf("the create path dropped the reported switch: %v", n.BlockIncoming)
	}
}
