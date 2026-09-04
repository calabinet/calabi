package core

import (
	"context"
	"errors"
	"testing"
)

func allowAllDoc() ACLPolicy {
	return ACLPolicy{ACLs: []ACLRule{{Action: "accept", Src: []string{"*"}, Dst: []string{"*"}, Ports: []string{"*"}}}}
}

// The case the preview exists for: a meshnet running on the allow-all default
// saves its first restrictive rule. Every pair it no longer covers shows up as
// "removed" — that count is what an admin needs to see BEFORE saving.
func TestDiffPoliciesShowsWhatAFirstRuleCuts(t *testing.T) {
	nodes := []*Node{
		{ID: 1, Name: "laptop", Tags: []string{"tag:laptop"}},
		{ID: 2, Name: "db", Tags: []string{"tag:server"}},
		{ID: 3, Name: "ci", Tags: []string{"tag:server"}},
	}
	// From allow-all (before == nil) to "laptops may reach servers".
	after := ACLPolicy{ACLs: []ACLRule{
		{Action: "accept", Src: []string{"tag:laptop"}, Dst: []string{"tag:server"}},
	}}
	d := DiffPolicies(nodes, nil, after)

	if d.Nodes != 3 || d.TotalPairs != 3 {
		t.Fatalf("nodes=%d pairs=%d, want 3/3", d.Nodes, d.TotalPairs)
	}
	// db↔ci is the pair that loses reachability (both servers, no rule covers it).
	if len(d.Removed) != 1 || d.Removed[0].AName != "db" || d.Removed[0].BName != "ci" {
		t.Fatalf("removed = %+v, want just db↔ci", d.Removed)
	}
	if len(d.Added) != 0 {
		t.Fatalf("added = %+v, want none (allow-all already had everything)", d.Added)
	}
	if d.Unchanged != 2 {
		t.Fatalf("unchanged = %d, want 2 (laptop↔db, laptop↔ci)", d.Unchanged)
	}
}

// Loosening a policy reports gains, and the pair list names both ends so the UI
// can say WHICH connections change, not just how many.
func TestDiffPoliciesReportsAdded(t *testing.T) {
	nodes := []*Node{{ID: 1, Name: "a"}, {ID: 2, Name: "b"}}
	before := ACLPolicy{ACLs: []ACLRule{{Action: "accept", Src: []string{"a"}, Dst: []string{"a"}}}}
	d := DiffPolicies(nodes, &before, allowAllDoc())
	if len(d.Added) != 1 || d.Added[0].AName != "a" || d.Added[0].BName != "b" {
		t.Fatalf("added = %+v, want a↔b", d.Added)
	}
	if len(d.Removed) != 0 {
		t.Fatalf("removed = %+v, want none", d.Removed)
	}
}

// A disabled node is already out of every netmap, so it must not inflate the
// "connections cut" number with links that don't exist.
func TestDiffPoliciesIgnoresDisabledNodes(t *testing.T) {
	nodes := []*Node{
		{ID: 1, Name: "a"},
		{ID: 2, Name: "b"},
		{ID: 3, Name: "parked", Disabled: true},
	}
	d := DiffPolicies(nodes, nil, ACLPolicy{ACLs: []ACLRule{
		{Action: "accept", Src: []string{"a"}, Dst: []string{"b"}},
	}})
	if d.Nodes != 2 || d.TotalPairs != 1 {
		t.Fatalf("nodes=%d pairs=%d, want 2/1 (parked node excluded)", d.Nodes, d.TotalPairs)
	}
	if len(d.Removed) != 0 {
		t.Fatalf("removed = %+v, want none", d.Removed)
	}
}

// An identical policy changes nothing — the preview must not cry wolf on a
// re-save (the console re-saves the same doc all the time).
func TestDiffPoliciesNoopEdit(t *testing.T) {
	nodes := []*Node{{ID: 1, Name: "a"}, {ID: 2, Name: "b"}, {ID: 3, Name: "c"}}
	p := allowAllDoc()
	d := DiffPolicies(nodes, &p, p)
	if len(d.Added)+len(d.Removed) != 0 || d.Unchanged != 3 {
		t.Fatalf("noop edit reported changes: %+v", d)
	}
}

// The checker names the rule that decided the answer, and is honest that the
// netmap layer is undirected: a one-way rule still opens the pair both ways
// (directional enforcement is MESH.5b).
func TestCheckAccessNamesTheRuleAndIsHonestAboutDirection(t *testing.T) {
	c := newTestCoord()
	store := NewMemACLStore()
	c.ACL = store
	ctx := context.Background()
	laptop, _ := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "laptop", NodeKey: key(1), Tags: []string{"tag:laptop"}})
	_, _ = c.Register(ctx, RegisterInput{Meshnet: 1, Name: "db", NodeKey: key(2), Tags: []string{"tag:server"}})
	_ = laptop

	doc := ACLPolicy{ACLs: []ACLRule{
		{Action: "accept", Src: []string{"nobody"}, Dst: []string{"nobody"}},
		{Action: "accept", Src: []string{"tag:laptop"}, Dst: []string{"tag:server"}},
	}}
	if err := store.SetACL(ctx, 1, doc); err != nil {
		t.Fatal(err)
	}

	got, err := c.CheckAccess(ctx, 1, "laptop", "db", nil) // nil = what's live
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !got.Forward || got.ForwardRule != 1 {
		t.Fatalf("forward = %v rule %d, want true via rule 1", got.Forward, got.ForwardRule)
	}
	if got.Reverse || got.ReverseRule != -1 {
		t.Fatalf("reverse = %v rule %d, want no matching rule", got.Reverse, got.ReverseRule)
	}
	// No reverse rule, yet the pair IS reachable — that's the undirected netmap
	// layer, and the UI has to say so.
	if !got.Reachable {
		t.Fatal("pair should be reachable: the netmap layer is undirected")
	}

	// Unknown node names are an error, not a silent "denied".
	if _, err := c.CheckAccess(ctx, 1, "laptop", "ghost", nil); err == nil {
		t.Fatal("unknown dst should error")
	}
}

// With no stored doc the meshnet runs allow-all, and the checker says so
// (reachable, with no rule to point at).
func TestCheckAccessAllowAllDefault(t *testing.T) {
	c := newTestCoord()
	c.ACL = NewMemACLStore()
	ctx := context.Background()
	_, _ = c.Register(ctx, RegisterInput{Meshnet: 1, Name: "a", NodeKey: key(1)})
	_, _ = c.Register(ctx, RegisterInput{Meshnet: 1, Name: "b", NodeKey: key(2)})

	got, err := c.CheckAccess(ctx, 1, "a", "b", nil)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !got.Reachable || !got.Forward || got.ForwardRule != -1 {
		t.Fatalf("allow-all default = %+v, want reachable with no rule index", got)
	}
}

// PreviewACL compares against what the meshnet runs on right now, not against
// an empty policy.
func TestPreviewACLUsesLiveBaseline(t *testing.T) {
	c := newTestCoord()
	store := NewMemACLStore()
	c.ACL = store
	ctx := context.Background()
	_, _ = c.Register(ctx, RegisterInput{Meshnet: 1, Name: "a", NodeKey: key(1)})
	_, _ = c.Register(ctx, RegisterInput{Meshnet: 1, Name: "b", NodeKey: key(2)})
	if err := store.SetACL(ctx, 1, allowAllDoc()); err != nil {
		t.Fatal(err)
	}

	// Narrowing to a rule that covers nothing cuts the only pair.
	d, err := c.PreviewACL(ctx, 1, ACLPolicy{ACLs: []ACLRule{
		{Action: "accept", Src: []string{"a"}, Dst: []string{"a"}},
	}})
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if len(d.Removed) != 1 {
		t.Fatalf("removed = %+v, want the a↔b pair", d.Removed)
	}
}

// SaveACL is the single write path: it validates, stores, and records history.
// A refused document must leave BOTH the live policy and the history untouched
// — a history that contains versions which were never live would be worse than
// no history at all.
func TestSaveACLRecordsHistoryAndRejectsInvalid(t *testing.T) {
	c := newTestCoord()
	c.ACL = NewMemACLStore()
	revs := NewMemACLRevisionStore()
	c.ACLRevisions = revs
	ctx := context.Background()

	first := allowAllDoc()
	if err := c.SaveACL(ctx, 1, first, "user:42"); err != nil {
		t.Fatalf("save: %v", err)
	}
	second := ACLPolicy{ACLs: []ACLRule{{Action: "accept", Src: []string{"a"}, Dst: []string{"b"}, Ports: []string{"*"}}}}
	if err := c.SaveACL(ctx, 1, second, "admin:7"); err != nil {
		t.Fatalf("save 2: %v", err)
	}

	// An empty doc is refused (the deny-all trap) and wrapped so the HTTP layer
	// can answer 400 rather than 500.
	err := c.SaveACL(ctx, 1, ACLPolicy{}, "user:42")
	if !errors.Is(err, ErrInvalidACL) {
		t.Fatalf("empty doc err = %v, want ErrInvalidACL", err)
	}

	got, err := c.ACLRevisionsFor(ctx, 1, 20)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("revisions = %d, want 2 (the refused save must not be recorded)", len(got))
	}
	if len(got[0].Policy.ACLs) != 1 || got[0].Actor != "admin:7" {
		t.Fatalf("newest revision = %+v, want the second save first", got[0])
	}
	if got[1].Actor != "user:42" {
		t.Fatalf("oldest revision actor = %q, want user:42", got[1].Actor)
	}
	// The live policy is the last accepted one, not the refused one.
	live, ok, _ := c.ACL.GetACL(ctx, 1)
	if !ok || len(live.ACLs) != 1 {
		t.Fatalf("live policy = %+v ok=%v, want the second doc", live, ok)
	}
	// limit caps the list.
	if got, _ := c.ACLRevisionsFor(ctx, 1, 1); len(got) != 1 {
		t.Fatalf("limit=1 returned %d", len(got))
	}
}

// History is optional: a coordinator with no revision store still saves rules.
func TestSaveACLWithoutRevisionStore(t *testing.T) {
	c := newTestCoord()
	c.ACL = NewMemACLStore()
	ctx := context.Background()
	if err := c.SaveACL(ctx, 1, allowAllDoc(), ""); err != nil {
		t.Fatalf("save without history: %v", err)
	}
	revs, err := c.ACLRevisionsFor(ctx, 1, 10)
	if err != nil || len(revs) != 0 {
		t.Fatalf("revisions = %v err = %v, want empty", revs, err)
	}
}
