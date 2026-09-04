package core

import (
	"errors"
	"testing"
)

// An admin's entry IS the authorization, so it starts confirmed. Asking someone
// to confirm what they just typed would be theatre, and it would also blur the
// line the two sources sit on: a device's claim needs a second human step, an
// admin's entry already is that step.
func TestConsoleServiceStartsConfirmed(t *testing.T) {
	c, ctx := serviceCoord(t)
	node, _ := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "db1", NodeKey: key(1)})

	svc, err := c.CreateConsoleService(ctx, 1, node.ID, "db", "tcp", 5432, "", "primary")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !svc.Approved {
		t.Error("an admin-authored service arrived unconfirmed")
	}
	if !svc.FromConsole() {
		t.Errorf("source = %q, want console", svc.Source)
	}
}

// THE regression this slice exists for. A daemon restart re-sends the machine's
// whole declared set, and reconciliation withdraws anything that set no longer
// names — which would wipe every console-authored row on the first restart.
func TestConsoleServiceSurvivesADeviceRestart(t *testing.T) {
	c, ctx := serviceCoord(t)
	node, _ := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "db1", NodeKey: key(1)})
	if _, err := c.CreateConsoleService(ctx, 1, node.ID, "db", "tcp", 5432, "", ""); err != nil {
		t.Fatalf("create: %v", err)
	}

	// The device re-registers declaring something else entirely.
	if _, err := c.Register(ctx, RegisterInput{
		Meshnet: 1, Name: "db1", NodeKey: key(1),
		DeclaredServices: []Service{declared("metrics", "tcp", 9090)},
	}); err != nil {
		t.Fatalf("re-register: %v", err)
	}

	svc, ok := svcNamed(t, c, 1, node.ID, "db")
	if !ok {
		t.Fatal("the console-authored service was withdrawn by a device restart")
	}
	if !svc.Approved || !svc.FromConsole() {
		t.Errorf("console row was rewritten by reconciliation: %+v", svc)
	}
}

// A device declaring the same NAME must not produce a second row. Two entries
// claiming one name, only one of them carrying the authorization, is the shape called a shadow record — and it is invisible in a list that shows names.
func TestDeviceDeclarationDoesNotShadowAConsoleService(t *testing.T) {
	c, ctx := serviceCoord(t)
	node, _ := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "db1", NodeKey: key(1)})
	if _, err := c.CreateConsoleService(ctx, 1, node.ID, "db", "tcp", 5432, "", ""); err != nil {
		t.Fatalf("create: %v", err)
	}

	// The machine claims the same name on a DIFFERENT port.
	if _, err := c.Register(ctx, RegisterInput{
		Meshnet: 1, Name: "db1", NodeKey: key(1),
		DeclaredServices: []Service{declared("db", "tcp", 9999)},
	}); err != nil {
		t.Fatalf("re-register: %v", err)
	}

	all, err := c.ServicesFor(ctx, 1)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	named := 0
	for _, s := range all {
		if s.NodeID == node.ID && s.Name == "db" {
			named++
			if s.Port != 5432 {
				t.Errorf("the device's claim overwrote the admin's port: %d", s.Port)
			}
		}
	}
	if named != 1 {
		t.Fatalf("%d rows named \"db\" on one node, want 1", named)
	}
}

// The node id in a request must not be enough to attach a service to a
// stranger's machine.
func TestConsoleServiceCannotTargetAnotherMeshnetsNode(t *testing.T) {
	c, ctx := serviceCoord(t)
	theirs, _ := c.Register(ctx, RegisterInput{Meshnet: 2, Name: "db1", NodeKey: key(1)})

	if _, err := c.CreateConsoleService(ctx, 1, theirs.ID, "db", "tcp", 5432, "", ""); !errors.Is(err, ErrNodeNotFound) {
		t.Fatalf("err = %v, want ErrNodeNotFound", err)
	}
	if list, _ := c.ServicesFor(ctx, 2); len(list) != 0 {
		t.Fatal("a service was attached to another meshnet's node")
	}
}

func TestConsoleServiceRejectsDuplicatesAndBadInput(t *testing.T) {
	c, ctx := serviceCoord(t)
	node, _ := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "db1", NodeKey: key(1)})
	if _, err := c.CreateConsoleService(ctx, 1, node.ID, "db", "tcp", 5432, "", ""); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := c.CreateConsoleService(ctx, 1, node.ID, "db", "tcp", 5433, "", ""); !errors.Is(err, ErrServiceExists) {
		t.Errorf("duplicate name on one node was accepted (err=%v)", err)
	}
	for name, tc := range map[string]struct {
		svc   string
		proto string
		port  int
	}{
		"bad name":  {"Not A Label!", "tcp", 5432},
		"bad proto": {"web", "sctp", 443},
		"bad port":  {"web", "tcp", 70000},
	} {
		if _, err := c.CreateConsoleService(ctx, 1, node.ID, tc.svc, tc.proto, tc.port, "", ""); !errors.Is(err, ErrInvalidService) {
			t.Errorf("%s: err = %v, want ErrInvalidService", name, err)
		}
	}
}

// Deleting a device-declared row would look like it failed: the machine's next
// registration puts it straight back, pending. Un-confirming is the action that
// actually means something, so the error says so.
func TestDeleteRefusesDeviceDeclaredServices(t *testing.T) {
	c, ctx := serviceCoord(t)
	node := declareApproved(t, c, ctx, RegisterInput{
		Meshnet: 1, Name: "db1", NodeKey: key(1),
		DeclaredServices: []Service{declared("db", "tcp", 5432)},
	})
	svc, ok := svcNamed(t, c, 1, node.ID, "db")
	if !ok {
		t.Fatal("setup: declaration not recorded")
	}
	if err := c.DeleteConsoleService(ctx, 1, svc.ID); !errors.Is(err, ErrInvalidService) {
		t.Fatalf("err = %v, want ErrInvalidService", err)
	}
	if _, still := svcNamed(t, c, 1, node.ID, "db"); !still {
		t.Fatal("the row was deleted anyway")
	}
}

func TestDeleteConsoleServiceIsScopedToTheMeshnet(t *testing.T) {
	c, ctx := serviceCoord(t)
	theirNode, _ := c.Register(ctx, RegisterInput{Meshnet: 2, Name: "db1", NodeKey: key(1)})
	theirs, err := c.CreateConsoleService(ctx, 2, theirNode.ID, "db", "tcp", 5432, "", "")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := c.DeleteConsoleService(ctx, 1, theirs.ID); !errors.Is(err, ErrServiceNotFound) {
		t.Fatalf("err = %v, want ErrServiceNotFound", err)
	}
	if list, _ := c.ServicesFor(ctx, 2); len(list) != 1 {
		t.Fatal("another meshnet's service was deleted")
	}
	if err := c.DeleteConsoleService(ctx, 2, theirs.ID); err != nil {
		t.Fatalf("owner could not delete its own: %v", err)
	}
}

// The admin approved a specific ENDPOINT. Where the traffic actually ends up —
// protocol, port, or the address behind them — is part of that endpoint, so
// changing any of them is a different thing to approve. A note is just prose.
func TestTargetChangeSendsAServiceBackForReview(t *testing.T) {
	c, ctx := serviceCoord(t)
	node := declareApproved(t, c, ctx, RegisterInput{
		Meshnet: 1, Name: "db1", NodeKey: key(1),
		DeclaredServices: []Service{{Name: "db", Proto: "tcp", Port: 5432, Target: "127.0.0.1:5432"}},
	})

	// Same port to peers, but the machine now forwards it somewhere else.
	if _, err := c.Register(ctx, RegisterInput{
		Meshnet: 1, Name: "db1", NodeKey: key(1),
		DeclaredServices: []Service{{Name: "db", Proto: "tcp", Port: 5432, Target: "192.168.1.50:5432"}},
	}); err != nil {
		t.Fatalf("re-register: %v", err)
	}
	svc, ok := svcNamed(t, c, 1, node.ID, "db")
	if !ok {
		t.Fatal("service vanished")
	}
	if svc.Approved {
		t.Error("the machine repointed the service at another host and kept its approval")
	}
	if svc.Target != "192.168.1.50:5432" {
		t.Errorf("target = %q, want the new one recorded", svc.Target)
	}

	// A note-only edit is not a new endpoint.
	if _, err := c.SetServiceApproved(ctx, 1, svc.ID, true); err != nil {
		t.Fatalf("re-approve: %v", err)
	}
	if _, err := c.Register(ctx, RegisterInput{
		Meshnet: 1, Name: "db1", NodeKey: key(1),
		DeclaredServices: []Service{{Name: "db", Proto: "tcp", Port: 5432, Target: "192.168.1.50:5432", Note: "primary"}},
	}); err != nil {
		t.Fatalf("re-register: %v", err)
	}
	svc, _ = svcNamed(t, c, 1, node.ID, "db")
	if !svc.Approved {
		t.Error("editing the note un-approved the service")
	}
}

// An empty target means loopback on the service's own port — the common case,
// and what makes publishing one as a tunnel need no extra information.
func TestTargetDefaultsToLoopback(t *testing.T) {
	if got := (Service{Port: 5432}).TargetAddr(); got != "127.0.0.1:5432" {
		t.Errorf("TargetAddr() = %q, want 127.0.0.1:5432", got)
	}
	if got := (Service{Port: 5432, Target: "192.168.1.50:6000"}).TargetAddr(); got != "192.168.1.50:6000" {
		t.Errorf("TargetAddr() = %q, want the explicit target", got)
	}
	for _, bad := range []string{"nope", "host:", ":5432", "host:0", "host:70000"} {
		if err := ValidateServiceTarget(bad); err == nil {
			t.Errorf("target %q was accepted", bad)
		}
	}
	if err := ValidateServiceTarget(""); err != nil {
		t.Errorf("empty target rejected: %v", err)
	}
}
