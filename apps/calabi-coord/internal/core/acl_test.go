package core

import (
	"context"
	"testing"
)

func names(ns []*Node) map[string]bool {
	m := make(map[string]bool, len(ns))
	for _, n := range ns {
		m[n.Name] = true
	}
	return m
}

func TestMemPolicyNodeNameRuleBidirectional(t *testing.T) {
	// accept a -> b. a and b must see each other; c sees no one.
	pol := MemPolicy{Policy: ACLPolicy{
		ACLs: []ACLRule{{Action: "accept", Src: []string{"node-a"}, Dst: []string{"node-b"}}},
	}}
	a := &Node{Name: "node-a"}
	b := &Node{Name: "node-b"}
	c := &Node{Name: "node-c"}
	ctx := context.Background()

	// a's candidates {b, c} -> only b (a may reach b).
	got, _ := pol.Filter(ctx, 1, a, []*Node{b, c})
	if n := names(got); !n["node-b"] || n["node-c"] || len(got) != 1 {
		t.Fatalf("a sees %v, want only node-b", n)
	}
	// b's candidates {a, c} -> only a (a may reach b => b visible to a and a to b).
	got, _ = pol.Filter(ctx, 1, b, []*Node{a, c})
	if n := names(got); !n["node-a"] || n["node-c"] || len(got) != 1 {
		t.Fatalf("b sees %v, want only node-a", n)
	}
	// c's candidates {a, b} -> none.
	got, _ = pol.Filter(ctx, 1, c, []*Node{a, b})
	if len(got) != 0 {
		t.Fatalf("c sees %v, want none", names(got))
	}
}

func TestMemPolicyStar(t *testing.T) {
	pol := MemPolicy{Policy: ACLPolicy{
		ACLs: []ACLRule{{Action: "accept", Src: []string{"*"}, Dst: []string{"*"}}},
	}}
	a := &Node{Name: "a"}
	got, _ := pol.Filter(context.Background(), 1, a, []*Node{{Name: "b"}, {Name: "c"}})
	if len(got) != 2 {
		t.Fatalf("star should see all, got %d", len(got))
	}
}

func TestMemPolicyEmptyDeniesAll(t *testing.T) {
	pol := MemPolicy{Policy: ACLPolicy{}}
	got, _ := pol.Filter(context.Background(), 1, &Node{Name: "a"}, []*Node{{Name: "b"}})
	if len(got) != 0 {
		t.Fatalf("empty policy should deny all, saw %d", len(got))
	}
}

func TestReloadablePolicySwap(t *testing.T) {
	rp := NewReloadablePolicy(ACLPolicy{}) // deny-all
	a := &Node{Name: "a"}
	b := &Node{Name: "b"}
	ctx := context.Background()
	if got, _ := rp.Filter(ctx, 1, a, []*Node{b}); len(got) != 0 {
		t.Fatalf("empty policy should deny, saw %d", len(got))
	}
	// Hot-swap in a policy that permits a -> b.
	rp.Set(ACLPolicy{ACLs: []ACLRule{{Action: "accept", Src: []string{"a"}, Dst: []string{"b"}}}})
	if got, _ := rp.Filter(ctx, 1, a, []*Node{b}); len(got) != 1 {
		t.Fatalf("after Set, a should see b, saw %d", len(got))
	}
}

func TestMemPolicyGroupAndTag(t *testing.T) {
	pol := MemPolicy{Policy: ACLPolicy{
		Groups: map[string][]string{"group:eng": {"node-a", "tag:ci"}},
		ACLs: []ACLRule{
			{Action: "accept", Src: []string{"group:eng"}, Dst: []string{"tag:prod"}},
		},
	}}
	a := &Node{Name: "node-a"}                            // in group via name
	ci := &Node{Name: "runner", Tags: []string{"tag:ci"}} // in group via tag
	prod := &Node{Name: "db", Tags: []string{"tag:prod"}}
	other := &Node{Name: "laptop"}
	ctx := context.Background()

	// a (eng) -> prod: visible.
	if got, _ := pol.Filter(ctx, 1, a, []*Node{prod, other}); !names(got)["db"] || names(got)["laptop"] {
		t.Fatalf("a should see only prod db, got %v", names(got))
	}
	// ci runner (eng) -> prod: visible.
	if got, _ := pol.Filter(ctx, 1, ci, []*Node{prod}); len(got) != 1 {
		t.Fatalf("ci runner should reach prod")
	}
	// prod sees eng members (reverse visibility for handshake).
	if got, _ := pol.Filter(ctx, 1, prod, []*Node{a, ci, other}); !names(got)["node-a"] || !names(got)["runner"] || names(got)["laptop"] {
		t.Fatalf("prod should see eng members only, got %v", names(got))
	}
}
