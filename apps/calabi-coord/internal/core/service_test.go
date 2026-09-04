package core

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func serviceCoord(t *testing.T) (*Coordinator, context.Context) {
	t.Helper()
	c := newTestCoord()
	c.Services = NewMemServiceStore()
	return c, context.Background()
}

// A declaration is normalized, validated, and pinned to its node; the same name
// declareApproved runs the ONLY path a service can enter by: the node declares
// it at registration, then an admin confirms it. Every service test goes through
// this so none of them can pass on a path production doesn't have.
//
// The declaration list is the node's WHOLE set each time, exactly as a config
// file is — passing a subset withdraws the rest, which is the intended
// behaviour and a real trap when writing these tests.
func declareApproved(t *testing.T, c *Coordinator, ctx context.Context, in RegisterInput) *Node {
	t.Helper()
	node, err := c.Register(ctx, in)
	if err != nil {
		t.Fatalf("register %s: %v", in.Name, err)
	}
	all, err := c.ServicesFor(ctx, in.Meshnet)
	if err != nil {
		t.Fatalf("list services: %v", err)
	}
	for _, s := range all {
		if s.NodeID != node.ID || s.Approved {
			continue
		}
		if _, err := c.SetServiceApproved(ctx, in.Meshnet, s.ID, true); err != nil {
			t.Fatalf("approve %s: %v", s.Name, err)
		}
	}
	return node
}

// on the SAME node collapses to one entry, while the same name on ANOTHER node
// is kept — three nodes serving "web" are one service with three instances.
// Names, protocols and notes are normalized on the way in.
func TestDeclarationUniquePerNodeNotPerMeshnet(t *testing.T) {
	c, ctx := serviceCoord(t)
	a := declareApproved(t, c, ctx, RegisterInput{Meshnet: 1, Name: "a", NodeKey: key(1),
		DeclaredServices: []Service{
			{Name: "  Postgres ", Proto: "TCP", Port: 5432, Note: " prod db "},
			{Name: "postgres", Proto: "tcp", Port: 5433}, // same name again: first wins
		}})
	b := declareApproved(t, c, ctx, RegisterInput{Meshnet: 1, Name: "b", NodeKey: key(2),
		DeclaredServices: []Service{{Name: "postgres", Proto: "tcp", Port: 5432}}})

	all, _ := c.ServicesFor(ctx, 1)
	onA := 0
	for _, s := range all {
		if s.NodeID != a.ID {
			continue
		}
		onA++
		if s.Name != "postgres" || s.Proto != "tcp" || s.Note != "prod db" || s.Port != 5432 {
			t.Fatalf("not normalized / wrong entry won: %+v", s)
		}
	}
	if onA != 1 {
		t.Fatalf("node a has %d entries named postgres, want 1", onA)
	}
	onB := 0
	for _, s := range all {
		if s.NodeID == b.ID && s.Name == "postgres" {
			onB++
		}
	}
	if onB != 1 {
		t.Fatalf("the same name on another node should be kept: %d", onB)
	}
}

// Bad declarations are refused: the name is an ACL selector, so it must be a
// label; the protocol and port must be real.
func TestServiceValidation(t *testing.T) {
	bad := []struct {
		name, proto string
		port        int
	}{
		{"", "tcp", 80},
		{"has space", "tcp", 80},
		{strings.Repeat("x", 64), "tcp", 80},
		{"web", "sctp", 80},
		{"web", "tcp", 0},
		{"web", "tcp", 70000},
	}
	for _, b := range bad {
		if err := ValidateService(b.name, b.proto, b.port); !errors.Is(err, ErrInvalidService) {
			t.Errorf("ValidateService(%q,%q,%d) err = %v, want ErrInvalidService", b.name, b.proto, b.port, err)
		}
	}
}

// The tenant boundary now sits on approval — the only service mutation left.
// A service id from another meshnet must be "not found", never approvable:
// approving another org's service would make their machine a valid target for
// our rules.
func TestServiceApprovalTenantBoundary(t *testing.T) {
	c, ctx := serviceCoord(t)
	theirs, _ := c.Register(ctx, RegisterInput{Meshnet: 2, Name: "theirs", NodeKey: key(2),
		DeclaredServices: []Service{{Name: "web", Proto: "tcp", Port: 80}}})

	all, _ := c.ServicesFor(ctx, 2)
	if len(all) != 1 {
		t.Fatalf("setup: services = %+v", all)
	}
	if _, err := c.SetServiceApproved(ctx, 1, all[0].ID, true); !errors.Is(err, ErrServiceNotFound) {
		t.Fatalf("cross-tenant approve err = %v, want ErrServiceNotFound", err)
	}
	after, _ := c.ServicesFor(ctx, 2)
	if after[0].Approved {
		t.Fatal("another meshnet's service was approved")
	}
	_ = theirs
}

// A coordinator without a registry doesn't crash; it just has no services.
func TestServicesWithoutRegistry(t *testing.T) {
	c := newTestCoord()
	ctx := context.Background()
	if got, err := c.ServicesFor(ctx, 1); err != nil || len(got) != 0 {
		t.Fatalf("ServicesFor = %v, %v; want empty", got, err)
	}
	if _, err := c.SetServiceApproved(ctx, 1, 1, true); err == nil {
		t.Fatal("approving without a registry should error")
	}
	// And a node declaring services against a registry-less coordinator still
	// enrolls — the declaration is simply dropped on the floor.
	if _, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "a", NodeKey: key(1),
		DeclaredServices: []Service{{Name: "web", Proto: "tcp", Port: 80}}}); err != nil {
		t.Fatalf("register with declarations and no registry: %v", err)
	}
}

// A service name decides a PORT, never a set of machines. Names are chosen by
// whoever runs the device and are unique only within it, so two people calling
// their own thing "web" have not formed a group — letting the name select
// machines would mean an unprivileged declaration silently widens an existing
// rule. The admin names the machines; the declaration only supplies the number,
// and supplies a DIFFERENT number per machine.
func TestServiceNamesAPortNotAGroupOfMachines(t *testing.T) {
	c, ctx := serviceCoord(t)
	c.ACL = NewMemACLStore()
	laptop, _ := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "laptop", NodeKey: key(1), Tags: []string{"tag:laptop"}})
	web1 := declareApproved(t, c, ctx, RegisterInput{Meshnet: 1, Name: "web1", NodeKey: key(2),
		DeclaredServices: []Service{{Name: "web", Proto: "tcp", Port: 443}}})
	web2 := declareApproved(t, c, ctx, RegisterInput{Meshnet: 1, Name: "web2", NodeKey: key(3),
		DeclaredServices: []Service{{Name: "web", Proto: "tcp", Port: 8443}}})
	// A machine nobody authorized, declaring the very same name.
	declareApproved(t, c, ctx, RegisterInput{Meshnet: 1, Name: "stranger", NodeKey: key(4),
		DeclaredServices: []Service{{Name: "web", Proto: "tcp", Port: 443}}})

	// The old spelling is refused outright.
	legacy := ACLPolicy{ACLs: []ACLRule{{Action: "accept",
		Src: []string{"tag:laptop"}, Dst: []string{"svc:web"}, Ports: []string{"*"}}}}
	if err := ValidateACLPolicy(legacy); err == nil {
		t.Fatal(`"svc:web" was accepted as a dst selector; a service must not select machines`)
	}

	doc := ACLPolicy{ACLs: []ACLRule{{Action: "accept",
		Src: []string{"tag:laptop"}, Dst: []string{"web1", "web2"}, Ports: []string{"svc:web"}}}}
	if err := c.SaveACL(ctx, 1, doc, "user:1"); err != nil {
		t.Fatalf("save: %v", err)
	}
	c.Policy = ACLFilter{Store: c.ACL, Fallback: AllowAllPolicy{}}

	nm, err := c.NetMapFor(ctx, laptop.ID)
	if err != nil {
		t.Fatalf("netmap: %v", err)
	}
	seen := map[string]bool{}
	for _, p := range nm.Peers {
		seen[p.Name] = true
	}
	if !seen["web1"] || !seen["web2"] {
		t.Fatalf("the named machines must be reachable: %v", seen)
	}
	if seen["stranger"] {
		t.Fatal("a machine that merely declares the same service name got in — " +
			"a self-chosen name must never widen a rule")
	}

	// The payoff of naming a service rather than a number: each destination
	// opens ITS OWN port under one rule.
	for _, tc := range []struct {
		node *Node
		want string
	}{{web1, "tcp 443-443"}, {web2, "tcp 8443-8443"}} {
		nm, err := c.NetMapFor(ctx, tc.node.ID)
		if err != nil {
			t.Fatalf("netmap %s: %v", tc.node.Name, err)
		}
		if got := portsOf(nm.PacketFilter); got != tc.want {
			t.Errorf("%s filter ports = %q, want %q", tc.node.Name, got, tc.want)
		}
	}

	// web2 stops declaring the service. It stays visible (an admin named it) but
	// the rule now opens no port on it — approval was for an endpoint that is
	// gone.
	if _, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "web2", NodeKey: key(3)}); err != nil {
		t.Fatalf("re-register web2 without the declaration: %v", err)
	}
	nm2, err := c.NetMapFor(ctx, web2.ID)
	if err != nil {
		t.Fatalf("netmap web2: %v", err)
	}
	if len(nm2.PacketFilter) != 0 {
		t.Fatalf("web2 no longer declares the service but still opens %+v", nm2.PacketFilter)
	}
}

// Documents stored before ports became a field keep enforcing exactly what they
// enforced: the read path never refuses a shape the write path has stopped
// accepting, or an upgrade would silently change every meshnet's rules.
func TestLegacyDocumentStillCompiles(t *testing.T) {
	c, ctx := serviceCoord(t)
	c.ACL = NewMemACLStore()
	laptop, _ := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "laptop", NodeKey: key(1), Tags: []string{"tag:laptop"}})
	web := declareApproved(t, c, ctx, RegisterInput{Meshnet: 1, Name: "web", NodeKey: key(2),
		DeclaredServices: []Service{{Name: "web", Proto: "tcp", Port: 443}}})
	db, _ := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "db", NodeKey: key(3), Tags: []string{"tag:server"}})

	// Straight into the store, bypassing SaveACL — this is a doc written before
	// the split, exactly as it sits in the database today.
	old := ACLPolicy{ACLs: []ACLRule{
		{Action: "accept", Src: []string{"tag:laptop"}, Dst: []string{"svc:web"}},
		{Action: "accept", Src: []string{"tag:laptop"}, Dst: []string{"tag:server:5432"}},
	}}
	if err := c.ACL.SetACL(ctx, 1, old); err != nil {
		t.Fatalf("seed: %v", err)
	}
	c.Policy = ACLFilter{Store: c.ACL, Fallback: AllowAllPolicy{}}

	nmW, err := c.NetMapFor(ctx, web.ID)
	if err != nil {
		t.Fatalf("netmap web: %v", err)
	}
	if got := portsOf(nmW.PacketFilter); got != "tcp 443-443" {
		t.Errorf("legacy svc: dst compiled to %q, want tcp 443-443", got)
	}
	nmD, err := c.NetMapFor(ctx, db.ID)
	if err != nil {
		t.Fatalf("netmap db: %v", err)
	}
	if got := portsOf(nmD.PacketFilter); got != "5432-5432" {
		t.Errorf("legacy port suffix compiled to %q, want 5432-5432", got)
	}
	// And it is still refused on the way IN, so the console must convert it.
	if err := c.SaveACL(ctx, 1, old, "user:1"); err == nil {
		t.Error("the legacy shape was accepted by the write path")
	}
	_ = laptop
}

// Regression: a port suffix on a PREFIXED selector used to break the whole
// selector (tag:server:22 matched no tag at all — a rule that looked like it
// granted access granted nothing). Legacy documents still reach this path.
func TestSelectorPortSuffixStripping(t *testing.T) {
	n := &Node{Name: "db", Tags: []string{"tag:server"}, Services: []Service{{Name: "web"}}}
	for _, sel := range []string{"db", "db:5432", "tag:server", "tag:server:22", "svc:web", "svc:web:443"} {
		if !matchSelector(sel, n, nil) {
			t.Errorf("selector %q should match", sel)
		}
	}
	for _, sel := range []string{"other", "tag:laptop", "svc:api", "tag:server:notaport"} {
		if matchSelector(sel, n, nil) {
			t.Errorf("selector %q should NOT match", sel)
		}
	}
}
