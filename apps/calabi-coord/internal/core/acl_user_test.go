// acl_user_test.go — the PERSON dimension: user:<id>, autogroup:member and the
// relational autogroup:self.
//
// The rule these exist for is one line:
//
//	{"action":"accept","src":["autogroup:member"],"dst":["autogroup:self"],"ports":["*"]}
//
// "everyone reaches their own devices and nobody else's", written once and
// correct after the next hire. Without a person dimension the same policy has to
// be spelled out per human and rewritten on every new laptop.
//
// RUN: go test./apps/calabi-coord/internal/core/ -run 'TestACLUser|TestACLAutogroup|TestSelectorPort' -v
package core

import (
	"context"
	"net/netip"
	"testing"
)

// owned builds a node belonging to a person (0 = nobody).
func owned(name string, owner int64, overlay string) *Node {
	n := &Node{Name: name, OwnerUserID: owner}
	if overlay != "" {
		n.Overlay = netip.MustParseAddr(overlay)
	}
	return n
}

func TestACLUserSelectorMatchesThatPersonsDevices(t *testing.T) {
	pol := MemPolicy{Policy: ACLPolicy{ACLs: []ACLRule{
		{Action: "accept", Src: []string{"user:7"}, Dst: []string{"tag:db"}, Ports: []string{"*"}},
	}}}
	db := &Node{Name: "db", Tags: []string{"tag:db"}}
	mine := owned("laptop", 7, "")
	theirs := owned("her-laptop", 9, "")
	unowned := owned("build-box", 0, "")
	ctx := context.Background()

	got, _ := pol.Filter(ctx, 1, mine, []*Node{db, theirs, unowned})
	if n := names(got); !n["db"] || len(got) != 1 {
		t.Fatalf("user:7 device sees %v, want only db", n)
	}
	if got, _ := pol.Filter(ctx, 1, theirs, []*Node{db}); len(got) != 0 {
		t.Fatalf("a different person matched user:7: %v", names(got))
	}
	// owner 0 is nobody, not "user 0" — it must never satisfy a user selector.
	if got, _ := pol.Filter(ctx, 1, unowned, []*Node{db}); len(got) != 0 {
		t.Fatalf("an unattributed device matched a user selector: %v", names(got))
	}
}

// The whole point: one rule, and each person ends up with exactly their own
// machines — no cross-talk, and no configuration per person.
func TestACLAutogroupSelfIsolatesPeoplePairwise(t *testing.T) {
	pol := MemPolicy{Policy: ACLPolicy{ACLs: []ACLRule{
		{Action: "accept", Src: []string{autogroupMember}, Dst: []string{autogroupSelf}, Ports: []string{"*"}},
	}}}
	a1 := owned("a-laptop", 7, "")
	a2 := owned("a-desktop", 7, "")
	b1 := owned("b-laptop", 9, "")
	srv := owned("build-box", 0, "") // tagged/unattributed: belongs to nobody
	ctx := context.Background()

	got, _ := pol.Filter(ctx, 1, a1, []*Node{a2, b1, srv})
	if n := names(got); !n["a-desktop"] || len(got) != 1 {
		t.Fatalf("a1 sees %v, want only its owner's other machine", n)
	}
	got, _ = pol.Filter(ctx, 1, b1, []*Node{a1, a2, srv})
	if len(got) != 0 {
		t.Fatalf("b1 sees %v, want nothing (its owner has one device)", names(got))
	}
}

// Two nodes that both belong to NOBODY are not each other's own devices. Getting
// this wrong drops every unattributed machine in the org into one shared pool
// that they can all reach.
//
// The source selector here is "*" ON PURPOSE. Written with autogroup:member it
// passes either way — that selector already excludes owner 0, so it masks the
// bug this test is for, and the test would be green whether sameOwner checks
// the owner is a real person or not. (It was, until a control run said so.)
func TestACLAutogroupSelfTreatsOwnerZeroAsNobody(t *testing.T) {
	pol := MemPolicy{Policy: ACLPolicy{ACLs: []ACLRule{
		{Action: "accept", Src: []string{"*"}, Dst: []string{autogroupSelf}, Ports: []string{"*"}},
	}}}
	srv := owned("build-box", 0, "")
	srv2 := owned("build-box-2", 0, "")
	if got, _ := pol.Filter(context.Background(), 1, srv, []*Node{srv2}); len(got) != 0 {
		t.Fatalf("two unowned machines matched autogroup:self: %v", names(got))
	}
	// And the packet filter, which is a separate implementation of the same rule.
	a := owned("a", 0, "100.64.0.1")
	b := owned("b", 0, "100.64.0.2")
	pf := &ACLPolicy{ACLs: []ACLRule{
		{Action: "accept", Src: []string{"*"}, Dst: []string{autogroupSelf}, Ports: []string{"*"}},
	}}
	if rules := CompilePacketFilter(a, []*Node{b}, pf); len(rules) != 0 {
		t.Fatalf("the filter opened one unowned machine to another: %+v", rules)
	}
}

// autogroup:self is relative to the SOURCE, so it cannot be a source itself. As
// a src selector it must match nothing rather than something surprising — and
// the write path refuses it outright (see the validation test below).
func TestACLAutogroupSelfAsSourceGrantsNothing(t *testing.T) {
	pol := MemPolicy{Policy: ACLPolicy{ACLs: []ACLRule{
		{Action: "accept", Src: []string{autogroupSelf}, Dst: []string{"*"}, Ports: []string{"*"}},
	}}}
	a := owned("a", 7, "")
	b := owned("b", 7, "")
	if got, _ := pol.Filter(context.Background(), 1, a, []*Node{b}); len(got) != 0 {
		t.Fatalf("autogroup:self as a SOURCE granted %v", names(got))
	}
}

func TestACLAutogroupMemberExcludesUnattributedMachines(t *testing.T) {
	pol := MemPolicy{Policy: ACLPolicy{ACLs: []ACLRule{
		{Action: "accept", Src: []string{autogroupMember}, Dst: []string{"tag:db"}, Ports: []string{"*"}},
	}}}
	db := &Node{Name: "db", Tags: []string{"tag:db"}}
	person := owned("laptop", 7, "")
	machine := owned("ci", 0, "")
	ctx := context.Background()

	if got, _ := pol.Filter(ctx, 1, person, []*Node{db}); len(got) != 1 {
		t.Fatalf("a person's device did not match autogroup:member")
	}
	if got, _ := pol.Filter(ctx, 1, machine, []*Node{db}); len(got) != 0 {
		t.Fatalf("an unattributed machine matched autogroup:member: %v", names(got))
	}
}

// A group is how a rule names a TEAM. Holding people rather than machine names
// is what keeps it correct when somebody gets a new laptop.
func TestACLGroupCanHoldPeople(t *testing.T) {
	pol := MemPolicy{Policy: ACLPolicy{
		Groups: map[string][]string{"group:eng": {"user:7", "tag:ci"}},
		ACLs: []ACLRule{
			{Action: "accept", Src: []string{"group:eng"}, Dst: []string{"tag:db"}, Ports: []string{"*"}},
		},
	}}
	db := &Node{Name: "db", Tags: []string{"tag:db"}}
	ctx := context.Background()

	// The person's brand-new machine, never named anywhere in the document.
	if got, _ := pol.Filter(ctx, 1, owned("new-laptop", 7, ""), []*Node{db}); len(got) != 1 {
		t.Fatal("a group member's new device did not inherit the rule")
	}
	// A tag member still works alongside.
	ci := &Node{Name: "ci", Tags: []string{"tag:ci"}}
	if got, _ := pol.Filter(ctx, 1, ci, []*Node{db}); len(got) != 1 {
		t.Fatal("a tag member of the group stopped matching")
	}
	if got, _ := pol.Filter(ctx, 1, owned("outsider", 9, ""), []*Node{db}); len(got) != 0 {
		t.Fatalf("a non-member matched the group: %v", names(got))
	}
}

// stripSelectorPort exists because "tag:server:22" must lose its port. "user:42"
// is the same SHAPE and must not — it would become "user", which matches nothing
// and grants nothing, silently.
func TestSelectorPortStrippingLeavesUserSelectorsAlone(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"user:42", "user:42"},
		{"tag:server:22", "tag:server"},
		{"db:5432", "db"},
		{"svc:web:443", "svc:web"},
		{"autogroup:self", "autogroup:self"},
	} {
		if got := stripSelectorPort(c.in); got != c.want {
			t.Errorf("stripSelectorPort(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// End to end: the id survives far enough to actually match.
	pol := MemPolicy{Policy: ACLPolicy{ACLs: []ACLRule{
		{Action: "accept", Src: []string{"user:42"}, Dst: []string{"*"}, Ports: []string{"*"}},
	}}}
	if got, _ := pol.Filter(context.Background(), 1, owned("mine", 42, ""), []*Node{{Name: "x"}}); len(got) != 1 {
		t.Fatal("user:42 matched nothing — the port stripper ate the id")
	}
}

// The packet filter is the second gate, and it compiles PER RECEIVER. With a
// relational destination the source set is no longer "everyone the src selector
// matches" — it is only those who share this receiver's owner.
func TestACLAutogroupSelfCompilesToOwnerOnlySources(t *testing.T) {
	pol := &ACLPolicy{ACLs: []ACLRule{
		{Action: "accept", Src: []string{autogroupMember}, Dst: []string{autogroupSelf}, Ports: []string{"*"}},
	}}
	self := owned("a-laptop", 7, "100.64.0.1")
	mine := owned("a-desktop", 7, "100.64.0.2")
	theirs := owned("b-laptop", 9, "100.64.0.3")

	rules := CompilePacketFilter(self, []*Node{mine, theirs}, pol)
	if len(rules) != 1 {
		t.Fatalf("compiled %d rules, want 1: %+v", len(rules), rules)
	}
	got := rules[0].SrcCIDRs
	if len(got) != 1 || got[0] != "100.64.0.2/32" {
		t.Fatalf("sources = %v, want only the same owner's machine", got)
	}
}

// The dangerous shortcut. sourceCIDRs collapses a "*" source to 0.0.0.0/0 so the
// common "any node" rule does not compile into a list that grows with the
// meshnet — but with a relational destination "any source" no longer means "any
// address", and keeping the shortcut would hand the whole meshnet the access one
// person was meant to get.
func TestACLAutogroupSelfDefeatsTheWildcardSourceShortcut(t *testing.T) {
	pol := &ACLPolicy{ACLs: []ACLRule{
		{Action: "accept", Src: []string{"*"}, Dst: []string{autogroupSelf}, Ports: []string{"*"}},
	}}
	self := owned("a-laptop", 7, "100.64.0.1")
	mine := owned("a-desktop", 7, "100.64.0.2")
	theirs := owned("b-laptop", 9, "100.64.0.3")

	rules := CompilePacketFilter(self, []*Node{mine, theirs}, pol)
	if len(rules) != 1 {
		t.Fatalf("compiled %d rules, want 1", len(rules))
	}
	for _, c := range rules[0].SrcCIDRs {
		if c == "0.0.0.0/0" || c == "::/0" {
			t.Fatalf("a relational rule compiled to a wildcard source: %v", rules[0].SrcCIDRs)
		}
	}
	if len(rules[0].SrcCIDRs) != 1 || rules[0].SrcCIDRs[0] != "100.64.0.2/32" {
		t.Fatalf("sources = %v, want only the same owner's machine", rules[0].SrcCIDRs)
	}
}

func TestACLUserSelectorValidation(t *testing.T) {
	rule := func(src, dst []string) ACLPolicy {
		return ACLPolicy{ACLs: []ACLRule{{Action: "accept", Src: src, Dst: dst, Ports: []string{"*"}}}}
	}
	ok := []ACLPolicy{
		rule([]string{"user:7"}, []string{"*"}),
		rule([]string{autogroupMember}, []string{autogroupSelf}),
		rule([]string{"*"}, []string{autogroupMember}),
	}
	for i, p := range ok {
		if err := ValidateACLPolicy(p); err != nil {
			t.Errorf("valid policy %d rejected: %v", i, err)
		}
	}

	bad := []struct {
		name string
		p    ACLPolicy
	}{
		// Relative to the source, so it has nothing to be relative to as one.
		{"self as src", rule([]string{autogroupSelf}, []string{"*"})},
		// A typo, or a rule copied out of Tailscale's docs. It would fall through
		// to "is this the node CALLED autogroup:admin" and grant nothing.
		{"unknown autogroup", rule([]string{"autogroup:admin"}, []string{"*"})},
		{"empty user", rule([]string{"user:"}, []string{"*"})},
		// An address, not an id — the coordinator has no directory.
		{"email user", rule([]string{"user:kenji@acme.dev"}, []string{"*"})},
		{"zero user", rule([]string{"user:0"}, []string{"*"})},
	}
	for _, c := range bad {
		if err := ValidateACLPolicy(c.p); err == nil {
			t.Errorf("%s: accepted a policy that can never match", c.name)
		}
	}

	// Groups may hold people, but not autogroups.
	good := ACLPolicy{
		Groups: map[string][]string{"group:eng": {"user:7"}},
		ACLs:   []ACLRule{{Action: "accept", Src: []string{"group:eng"}, Dst: []string{"*"}, Ports: []string{"*"}}},
	}
	if err := ValidateACLPolicy(good); err != nil {
		t.Errorf("a group holding a user was rejected: %v", err)
	}
	nested := ACLPolicy{
		Groups: map[string][]string{"group:eng": {autogroupMember}},
		ACLs:   []ACLRule{{Action: "accept", Src: []string{"group:eng"}, Dst: []string{"*"}, Ports: []string{"*"}}},
	}
	if err := ValidateACLPolicy(nested); err == nil {
		t.Error("a group holding an autogroup was accepted")
	}
}
