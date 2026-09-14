// node_os_test.go — the platform a node reports, and the rule that keeps it.
//
// Node.OS exists so a peer list can say which machine is the Windows box. The
// interesting part is not storing it; it is that a daemon which does NOT report
// it must not erase what a newer one stored. Every daemon predating the field
// sends "" on every re-register and on every declaration push, and those happen
// constantly — so "apply only when non-empty" is the whole difference between a
// column that fills in and one that flickers empty for half a fleet.
//
// RUN: go test./apps/calabi-coord/internal/core/ -run TestNodeOS -v
package core

import (
	"context"
	"testing"
)

func TestNodeOSSurvivesADaemonThatDoesNotReportIt(t *testing.T) {
	c := newTestCoord()
	ctx := context.Background()

	n, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "box", NodeKey: key(1), OS: "windows"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if n.OS != "windows" {
		t.Fatalf("OS = %q, want windows", n.OS)
	}

	// The same node re-registers from a build that predates the field.
	n, err = c.Register(ctx, RegisterInput{Meshnet: 1, Name: "box", NodeKey: key(1)})
	if err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if n.OS != "windows" {
		t.Fatalf("an empty report erased a stored platform: OS = %q", n.OS)
	}

	// And a declaration push from that same older build must not erase it
	// either — this is the path an in-place upgrade takes most often.
	n, err = c.UpdateDeclarations(ctx, UpdateDeclarationsInput{Meshnet: 1, NodeKey: key(1)})
	if err != nil {
		t.Fatalf("update declarations: %v", err)
	}
	if n.OS != "windows" {
		t.Fatalf("a declaration push with no OS erased it: OS = %q", n.OS)
	}
}

func TestNodeOSIsUpdatedWhenReported(t *testing.T) {
	c := newTestCoord()
	ctx := context.Background()
	if _, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "box", NodeKey: key(1), OS: "linux"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	// Reinstalled onto another platform: a real report always wins.
	n, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "box", NodeKey: key(1), OS: "darwin"})
	if err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if n.OS != "darwin" {
		t.Fatalf("OS = %q, want darwin", n.OS)
	}
	n, err = c.UpdateDeclarations(ctx, UpdateDeclarationsInput{Meshnet: 1, NodeKey: key(1), OS: "windows"})
	if err != nil {
		t.Fatalf("update declarations: %v", err)
	}
	if n.OS != "windows" {
		t.Fatalf("a declaration push reporting an OS must apply it: OS = %q", n.OS)
	}
}
