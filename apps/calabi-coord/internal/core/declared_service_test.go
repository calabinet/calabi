package core

import (
	"context"
	"strconv"
	"testing"
)

func declared(name, proto string, port int) Service {
	return Service{Name: name, Proto: proto, Port: port}
}

func svcNamed(t *testing.T, c *Coordinator, meshnet MeshnetID, nodeID int64, name string) (Service, bool) {
	t.Helper()
	all, err := c.ServicesFor(context.Background(), meshnet)
	if err != nil {
		t.Fatalf("list services: %v", err)
	}
	for _, s := range all {
		if s.NodeID == nodeID && s.Name == name {
			return s, true
		}
	}
	return Service{}, false
}

// A node's declaration is a CLAIM: it is recorded, but until an admin confirms
// it, a rule naming that service opens NOTHING. Confirmation is the moment the
// device's self-report becomes an authorization — without it a machine could
// point a granted service name at any port it liked.
func TestDeclaredServiceOpensNoPortUntilConfirmed(t *testing.T) {
	c, ctx := serviceCoord(t)
	c.ACL = NewMemACLStore()
	_, _ = c.Register(ctx, RegisterInput{Meshnet: 1, Name: "laptop", NodeKey: key(1), Tags: []string{"tag:laptop"}})
	web, _ := c.Register(ctx, RegisterInput{
		Meshnet: 1, Name: "web", NodeKey: key(2),
		DeclaredServices: []Service{declared("web", "tcp", 443)},
	})

	got, ok := svcNamed(t, c, 1, web.ID, "web")
	if !ok {
		t.Fatal("declaration was not recorded")
	}
	if got.Approved {
		t.Error("a node's declaration was auto-approved")
	}

	doc := ACLPolicy{ACLs: []ACLRule{{Action: "accept",
		Src: []string{"tag:laptop"}, Dst: []string{"web"}, Ports: []string{"svc:web"}}}}
	if err := c.SaveACL(ctx, 1, doc, "user:1"); err != nil {
		t.Fatalf("save acl: %v", err)
	}
	// newTestCoord ships AllowAllPolicy; point the coordinator at the ACL we
	// just saved or the rule under test never runs.
	c.Policy = ACLFilter{Store: c.ACL, Fallback: AllowAllPolicy{}}

	nm, err := c.NetMapFor(ctx, web.ID)
	if err != nil {
		t.Fatalf("netmap: %v", err)
	}
	if len(nm.PacketFilter) != 0 {
		t.Fatalf("an UNCONFIRMED declaration opened %+v, want nothing", nm.PacketFilter)
	}

	// Confirming it is what makes the rule bite.
	if _, err := c.SetServiceApproved(ctx, 1, got.ID, true); err != nil {
		t.Fatalf("approve: %v", err)
	}
	nm, err = c.NetMapFor(ctx, web.ID)
	if err != nil {
		t.Fatalf("netmap after approve: %v", err)
	}
	if p := portsOf(nm.PacketFilter); p != "tcp 443-443" {
		t.Fatalf("after confirmation ports = %q, want tcp 443-443", p)
	}
}

// Re-registering with the same declaration must not disturb the admin's
// decision — a daemon restart happens constantly and cannot un-approve things.
func TestDeclaredServiceRestartKeepsApproval(t *testing.T) {
	c, ctx := serviceCoord(t)
	in := RegisterInput{Meshnet: 1, Name: "web", NodeKey: key(1), DeclaredServices: []Service{declared("web", "tcp", 443)}}
	node, _ := c.Register(ctx, in)
	s, _ := svcNamed(t, c, 1, node.ID, "web")
	if _, err := c.SetServiceApproved(ctx, 1, s.ID, true); err != nil {
		t.Fatalf("approve: %v", err)
	}

	if _, err := c.Register(ctx, in); err != nil {
		t.Fatalf("re-register: %v", err)
	}
	again, ok := svcNamed(t, c, 1, node.ID, "web")
	if !ok || !again.Approved {
		t.Fatalf("approval lost across a restart: %+v", again)
	}
	if again.ID != s.ID {
		t.Errorf("service id churned across a restart: %d then %d", s.ID, again.ID)
	}
}

// The admin approved a specific endpoint. Moving the service to another port is
// a different endpoint, so it goes back to pending rather than carrying the old
// approval to a new port.
func TestDeclaredServicePortChangeRePends(t *testing.T) {
	c, ctx := serviceCoord(t)
	node, _ := c.Register(ctx, RegisterInput{
		Meshnet: 1, Name: "web", NodeKey: key(1),
		DeclaredServices: []Service{declared("web", "tcp", 443)},
	})
	s, _ := svcNamed(t, c, 1, node.ID, "web")
	if _, err := c.SetServiceApproved(ctx, 1, s.ID, true); err != nil {
		t.Fatalf("approve: %v", err)
	}

	if _, err := c.Register(ctx, RegisterInput{
		Meshnet: 1, Name: "web", NodeKey: key(1),
		DeclaredServices: []Service{declared("web", "tcp", 8443)},
	}); err != nil {
		t.Fatalf("re-register: %v", err)
	}
	got, _ := svcNamed(t, c, 1, node.ID, "web")
	if got.Port != 8443 {
		t.Errorf("port = %d, want 8443", got.Port)
	}
	if got.Approved {
		t.Error("approval survived an endpoint change")
	}

	// A note-only edit is cosmetic and must NOT re-pend.
	if _, err := c.SetServiceApproved(ctx, 1, got.ID, true); err != nil {
		t.Fatalf("re-approve: %v", err)
	}
	if _, err := c.Register(ctx, RegisterInput{
		Meshnet: 1, Name: "web", NodeKey: key(1),
		DeclaredServices: []Service{{Name: "web", Proto: "tcp", Port: 8443, Note: "prod"}},
	}); err != nil {
		t.Fatalf("re-register with note: %v", err)
	}
	got, _ = svcNamed(t, c, 1, node.ID, "web")
	if !got.Approved || got.Note != "prod" {
		t.Errorf("note edit disturbed approval: %+v", got)
	}
}

// Dropping a declaration withdraws it: a machine that no longer offers a service
// must stop being a valid target for rules about it. Mirrors approved-intersect-
// claimed for subnet routes.
func TestDeclaredServiceWithdrawnWhenNoLongerDeclared(t *testing.T) {
	c, ctx := serviceCoord(t)
	node, _ := c.Register(ctx, RegisterInput{
		Meshnet: 1, Name: "web", NodeKey: key(1),
		DeclaredServices: []Service{declared("web", "tcp", 443), declared("api", "tcp", 8080)},
	})
	if _, ok := svcNamed(t, c, 1, node.ID, "api"); !ok {
		t.Fatal("api was not recorded")
	}

	if _, err := c.Register(ctx, RegisterInput{
		Meshnet: 1, Name: "web", NodeKey: key(1),
		DeclaredServices: []Service{declared("web", "tcp", 443)},
	}); err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if _, ok := svcNamed(t, c, 1, node.ID, "api"); ok {
		t.Error("a withdrawn declaration is still registered")
	}
	if _, ok := svcNamed(t, c, 1, node.ID, "web"); !ok {
		t.Error("the still-declared service was withdrawn too")
	}
}

// A typo in a config file costs that one line, not the machine's enrollment.
func TestDeclaredServiceBadEntriesAreSkippedNotFatal(t *testing.T) {
	c, ctx := serviceCoord(t)
	node, err := c.Register(ctx, RegisterInput{
		Meshnet: 1, Name: "web", NodeKey: key(1),
		DeclaredServices: []Service{
			declared("Bad Name!", "tcp", 443),
			declared("weird", "sctp", 443),
			declared("huge", "tcp", 70000),
			declared("good", "tcp", 443),
		},
	})
	if err != nil {
		t.Fatalf("a bad declaration blocked enrollment: %v", err)
	}
	if _, ok := svcNamed(t, c, 1, node.ID, "good"); !ok {
		t.Error("the valid declaration was dropped along with the bad ones")
	}
	all, _ := c.ServicesFor(ctx, 1)
	if len(all) != 1 {
		t.Fatalf("services = %+v, want only the valid one", all)
	}
}

// One node cannot flood the pending list.
func TestDeclaredServicesAreCapped(t *testing.T) {
	c, ctx := serviceCoord(t)
	var many []Service
	for i := 0; i < maxDeclaredServicesPerNode+10; i++ {
		many = append(many, declared("svc"+strconv.Itoa(i), "tcp", 1000+i))
	}
	if _, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "n", NodeKey: key(1), DeclaredServices: many}); err != nil {
		t.Fatalf("register: %v", err)
	}
	all, _ := c.ServicesFor(ctx, 1)
	if len(all) != maxDeclaredServicesPerNode {
		t.Fatalf("recorded %d services, want the cap of %d", len(all), maxDeclaredServicesPerNode)
	}
}
