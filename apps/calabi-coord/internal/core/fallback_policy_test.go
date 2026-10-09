package core

import (
	"context"
	"errors"
	"testing"
)

// A meshnet with no doc saved through the admin API runs on ACLFilter's
// Fallback — on a self-hosted coordinator, the CALABI_COORD_POLICY_FILE policy.
// These tests hold the rest of the coordinator to the SAME document the peer
// list is cut with: the packet filter each node enforces, and the answers the
// access checker and the save preview give an admin.

// fileRule is the policy file's one rule: dev machines may reach the database
// machines on 5432, and on nothing else.
func fileRule() ACLPolicy {
	return ACLPolicy{ACLs: []ACLRule{
		{Action: "accept", Src: []string{"tag:dev"}, Dst: []string{"tag:db"}, Ports: []string{"5432"}},
	}}
}

// fileCoord wires the coordinator the way wire() does with a policy file: one
// ACL store for the admin API (empty — nothing was ever saved through it) and
// the file behind it as the fallback.
func fileCoord(t *testing.T, file *ReloadablePolicy) (*Coordinator, context.Context) {
	t.Helper()
	c := newTestCoord()
	c.ACL = NewMemACLStore()
	c.Policy = ACLFilter{Store: c.ACL, Fallback: file}
	return c, context.Background()
}

func registerNode(t *testing.T, c *Coordinator, ctx context.Context, in RegisterInput) *Node {
	t.Helper()
	n, err := c.Register(ctx, in)
	if err != nil {
		t.Fatalf("register %s: %v", in.Name, err)
	}
	return n
}

func netMap(t *testing.T, c *Coordinator, ctx context.Context, n *Node) *NetMap {
	t.Helper()
	nm, err := c.NetMapFor(ctx, n.ID)
	if err != nil {
		t.Fatalf("netmap for %s: %v", n.Name, err)
	}
	return nm
}

func hasPeer(nm *NetMap, name string) bool {
	for _, p := range nm.Peers {
		if p.Name == name {
			return true
		}
	}
	return false
}

// The file's ports reach the filter the destination enforces, not only the peer
// list. Before, the filter compiled from "no stored doc" = allow-all: db let
// every port in from everywhere while its peer list said only dev, and dev
// accepted anything from db, so a one-way rule on one port was two-way on all.
func TestFallbackPolicyPortsReachThePacketFilter(t *testing.T) {
	c, ctx := fileCoord(t, NewReloadablePolicy(fileRule()))
	dev := registerNode(t, c, ctx, RegisterInput{Meshnet: 1, Name: "dev", NodeKey: key(1), Tags: []string{"tag:dev"}})
	db := registerNode(t, c, ctx, RegisterInput{Meshnet: 1, Name: "db", NodeKey: key(2), Tags: []string{"tag:db"}})
	other := registerNode(t, c, ctx, RegisterInput{Meshnet: 1, Name: "other", NodeKey: key(3)})

	devNM, dbNM, otherNM := netMap(t, c, ctx, dev), netMap(t, c, ctx, db), netMap(t, c, ctx, other)

	// The peer lists already followed the file; this is the half that worked.
	if !hasPeer(devNM, "db") || !hasPeer(dbNM, "dev") || hasPeer(otherNM, "db") {
		t.Fatalf("peers: dev=%+v db=%+v other=%+v, want only dev↔db", devNM.Peers, dbNM.Peers, otherNM.Peers)
	}

	// db opens 5432, to dev, and nothing else.
	if len(dbNM.PacketFilter) != 1 || portsOf(dbNM.PacketFilter) != "5432-5432" {
		t.Fatalf("db's filter = %+v, want one rule for port 5432", dbNM.PacketFilter)
	}
	if srcs := dbNM.PacketFilter[0].SrcCIDRs; len(srcs) != 1 || srcs[0] != hostCIDR(dev.Overlay) {
		t.Fatalf("db admits %v, want dev (%s) only", srcs, hostCIDR(dev.Overlay))
	}
	// dev and other are no rule's destination, so neither opens anything.
	if len(devNM.PacketFilter) != 0 || len(otherNM.PacketFilter) != 0 {
		t.Fatalf("dev's filter = %+v, other's = %+v; want both empty", devNM.PacketFilter, otherNM.PacketFilter)
	}
}

// The file is hot-reloaded, and a doc saved through the admin API replaces it
// for that meshnet: the filter has to follow both, on the next netmap.
func TestFallbackPolicyFilterFollowsReloadAndSavedDoc(t *testing.T) {
	file := NewReloadablePolicy(fileRule())
	c, ctx := fileCoord(t, file)
	registerNode(t, c, ctx, RegisterInput{Meshnet: 1, Name: "dev", NodeKey: key(1), Tags: []string{"tag:dev"}})
	db := registerNode(t, c, ctx, RegisterInput{Meshnet: 1, Name: "db", NodeKey: key(2), Tags: []string{"tag:db"}})

	file.Set(ACLPolicy{ACLs: []ACLRule{
		{Action: "accept", Src: []string{"tag:dev"}, Dst: []string{"tag:db"}, Ports: []string{"tcp:6432"}},
	}})
	if p := portsOf(netMap(t, c, ctx, db).PacketFilter); p != "tcp 6432-6432" {
		t.Fatalf("after the file changed, db's filter opens %q, want tcp 6432 only", p)
	}

	if err := c.SaveACL(ctx, 1, ACLPolicy{ACLs: []ACLRule{
		{Action: "accept", Src: []string{"tag:dev"}, Dst: []string{"tag:db"}, Ports: []string{"22"}},
	}}, "user:1"); err != nil {
		t.Fatal(err)
	}
	if p := portsOf(netMap(t, c, ctx, db).PacketFilter); p != "22-22" {
		t.Fatalf("with a saved doc, db's filter opens %q, want 22 only (the doc replaces the file)", p)
	}
}

// A policy file that is broken at startup fails closed: policyStore seeds the
// fallback with an EMPTY document until a good load. Empty is deny-all, not
// "no policy", and has to read that way in the filter too — an empty filter
// (which a node enforcing FilterEnabled reads as "nothing may reach me"), not
// the allow-all that a nil document compiles to.
func TestFallbackPolicyBrokenAtStartDeniesInBothGates(t *testing.T) {
	c, ctx := fileCoord(t, NewReloadablePolicy(ACLPolicy{}))
	a := registerNode(t, c, ctx, RegisterInput{Meshnet: 1, Name: "a", NodeKey: key(1)})
	registerNode(t, c, ctx, RegisterInput{Meshnet: 1, Name: "b", NodeKey: key(2)})

	nm := netMap(t, c, ctx, a)
	if len(nm.Peers) != 0 {
		t.Fatalf("peers = %+v, want none", nm.Peers)
	}
	if len(nm.PacketFilter) != 0 {
		t.Fatalf("filter = %+v, want empty (deny-all)", nm.PacketFilter)
	}
	got, err := c.CheckAccess(ctx, 1, "b", "a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Reachable || got.Forward || got.Reverse {
		t.Fatalf("check = %+v, want unreachable in both directions", got)
	}
}

// The access checker and the save preview describe what the meshnet runs on:
// the file, not an allow-all it isn't running.
func TestFallbackPolicyIsTheCheckAndPreviewBaseline(t *testing.T) {
	c, ctx := fileCoord(t, NewReloadablePolicy(fileRule()))
	registerNode(t, c, ctx, RegisterInput{Meshnet: 1, Name: "dev", NodeKey: key(1), Tags: []string{"tag:dev"}})
	registerNode(t, c, ctx, RegisterInput{Meshnet: 1, Name: "db", NodeKey: key(2), Tags: []string{"tag:db"}})
	registerNode(t, c, ctx, RegisterInput{Meshnet: 1, Name: "other", NodeKey: key(3)})

	got, err := c.CheckAccess(ctx, 1, "dev", "db", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Forward || got.ForwardRule != 0 || got.Reverse || got.ReverseRule != -1 || !got.Reachable {
		t.Fatalf("dev→db = %+v, want forward by rule 0, no reverse rule", got)
	}
	got, err = c.CheckAccess(ctx, 1, "other", "db", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Reachable || got.Forward || got.Reverse {
		t.Fatalf("other→db = %+v, want unreachable: no rule in the file names other", got)
	}

	// Saving the file's own rules through the admin API changes nothing, and
	// the preview has to say so rather than report cuts that already happened.
	d, err := c.PreviewACL(ctx, 1, fileRule())
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Added) != 0 || len(d.Removed) != 0 || d.Unchanged != d.TotalPairs {
		t.Fatalf("preview of the rules already in force = %+v, want no change", d)
	}
}

// opaquePolicy is a policy source the coordinator was never taught to read as
// a document: it filters peers, and that is all anyone can see of it.
type opaquePolicy struct{}

func (opaquePolicy) Filter(_ context.Context, _ MeshnetID, _ *Node, candidates []*Node) ([]*Node, error) {
	return candidates[:0], nil
}

// A fallback whose document can't be read must not compile as allow-all —
// that is how this whole hole looked from the outside: the right peers, and
// every port open. No map beats that map.
func TestFallbackPolicyUnreadableIsNotAllowAll(t *testing.T) {
	c, ctx := newTestCoord(), context.Background()
	c.ACL = NewMemACLStore()
	c.Policy = ACLFilter{Store: c.ACL, Fallback: opaquePolicy{}}
	a := registerNode(t, c, ctx, RegisterInput{Meshnet: 1, Name: "a", NodeKey: key(1)})

	if nm, err := c.NetMapFor(ctx, a.ID); err == nil {
		t.Fatalf("netmap built from a policy nobody could read, with filter %+v", nm.PacketFilter)
	}
}

// failingACLStore is an ACL store whose database is down.
type failingACLStore struct{}

var errACLStoreDown = errors.New("acl store unavailable")

func (failingACLStore) GetACL(context.Context, MeshnetID) (ACLPolicy, bool, error) {
	return ACLPolicy{}, false, errACLStoreDown
}

func (failingACLStore) SetACL(context.Context, MeshnetID, ACLPolicy) error { return errACLStoreDown }

// A store that cannot be read says nothing about whether the meshnet has a doc
// of its own, so falling back to the file would be a guess — and the guess could
// be the one that opens more than the meshnet's saved doc does. Every reader of
// the live policy refuses instead.
func TestFallbackPolicyNotUsedWhenTheStoreFails(t *testing.T) {
	c, ctx := newTestCoord(), context.Background()
	c.ACL = failingACLStore{}
	c.Policy = ACLFilter{Store: c.ACL, Fallback: NewReloadablePolicy(fileRule())}
	registerNode(t, c, ctx, RegisterInput{Meshnet: 1, Name: "dev", NodeKey: key(1), Tags: []string{"tag:dev"}})
	db := registerNode(t, c, ctx, RegisterInput{Meshnet: 1, Name: "db", NodeKey: key(2), Tags: []string{"tag:db"}})

	if _, err := c.NetMapFor(ctx, db.ID); !errors.Is(err, errACLStoreDown) {
		t.Fatalf("netmap err = %v, want the store error", err)
	}
	if _, err := c.CheckAccess(ctx, 1, "dev", "db", nil); !errors.Is(err, errACLStoreDown) {
		t.Fatalf("check err = %v, want the store error", err)
	}
	if _, err := c.PreviewACL(ctx, 1, fileRule()); !errors.Is(err, errACLStoreDown) {
		t.Fatalf("preview err = %v, want the store error", err)
	}
}
