package core

import (
	"context"
	"testing"
)

func node(id int64, name string, tags ...string) *Node {
	return &Node{ID: id, Name: name, Tags: tags}
}

// allowAB is a doc that only lets "a" and "b" reach each other.
var allowAB = ACLPolicy{ACLs: []ACLRule{{Action: "accept", Src: []string{"a"}, Dst: []string{"b"}}}}

func TestACLFilterPerMeshnet(t *testing.T) {
	ctx := context.Background()
	store := NewMemACLStore()
	_ = store.SetACL(ctx, 1, allowAB) // meshnet 1 restricted; meshnet 2 has no doc

	// Fallback is allow-all (the platform default when a meshnet has no doc).
	f := ACLFilter{Store: store, Fallback: AllowAllPolicy{}}

	self := node(1, "a")
	cands := []*Node{node(2, "b"), node(3, "c")}

	// Meshnet 1: only b is reachable from a (c has no rule).
	got, err := f.Filter(ctx, 1, self, cands)
	if err != nil {
		t.Fatalf("filter m1: %v", err)
	}
	if n := names(got); !n["b"] || n["c"] || len(got) != 1 {
		t.Fatalf("meshnet 1 peers = %v, want just b", names(got))
	}

	// Meshnet 2 (no stored doc) → fallback allow-all → both peers visible.
	got, err = f.Filter(ctx, 2, self, cands)
	if err != nil {
		t.Fatalf("filter m2: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("meshnet 2 (no doc) peers = %d, want 2 (allow-all fallback)", len(got))
	}
}

func TestACLFilterEmptyDocIsDenyAll(t *testing.T) {
	ctx := context.Background()
	store := NewMemACLStore()
	// An explicit doc with NO rules = deny-all (an admin's deliberate lockdown),
	// distinct from "no doc" which is allow-all.
	_ = store.SetACL(ctx, 1, ACLPolicy{})
	f := ACLFilter{Store: store, Fallback: AllowAllPolicy{}}
	got, err := f.Filter(ctx, 1, node(1, "a"), []*Node{node(2, "b")})
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("empty doc peers = %d, want 0 (deny-all)", len(got))
	}
}

func TestACLFilterTagsAndGroups(t *testing.T) {
	ctx := context.Background()
	store := NewMemACLStore()
	_ = store.SetACL(ctx, 1, ACLPolicy{
		Groups: map[string][]string{"group:ops": {"tag:server"}},
		ACLs:   []ACLRule{{Action: "accept", Src: []string{"tag:laptop"}, Dst: []string{"group:ops"}}},
	})
	f := ACLFilter{Store: store, Fallback: AllowAllPolicy{}}
	self := node(1, "alex-laptop", "tag:laptop")
	cands := []*Node{node(2, "db", "tag:server"), node(3, "random")}
	got, err := f.Filter(ctx, 1, self, cands)
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if n := names(got); !n["db"] || n["random"] || len(got) != 1 {
		t.Fatalf("peers = %v, want just db (tag:server via group:ops)", names(got))
	}
}

func TestValidateACLPolicy(t *testing.T) {
	ok := []ACLPolicy{
		{ACLs: []ACLRule{{Action: "accept", Src: []string{"*"}, Dst: []string{"*"}, Ports: []string{"*"}}}},
		{Groups: map[string][]string{"group:ops": {"a", "tag:server"}},
			ACLs: []ACLRule{{Action: "accept", Src: []string{"group:ops"}, Dst: []string{"tag:server"}, Ports: []string{"22"}}}},
		{ACLs: []ACLRule{{Action: "accept", Src: []string{"*"}, Dst: []string{"db"},
			Ports: []string{"tcp:5432", "udp:53", "8000-8100", "svc:web"}}}},
	}
	for i, p := range ok {
		if err := ValidateACLPolicy(p); err != nil {
			t.Fatalf("valid doc %d rejected: %v", i, err)
		}
	}

	bad := map[string]ACLPolicy{
		// A doc with no rules is deny-everything (there is no deny action, so
		// "no rules" is not "no policy"). Saving one cuts every node pair at once,
		// and it is what an admin produces by deleting the last rule — so the
		// write path refuses it and points at the two things they actually meant.
		"empty doc (deny-all trap)": {},
		"groups but no rules":       {Groups: map[string][]string{"group:ops": {"a"}}},
		"non-accept action":         {ACLs: []ACLRule{{Action: "deny", Src: []string{"*"}, Dst: []string{"*"}, Ports: []string{"*"}}}},
		"missing dst":               {ACLs: []ACLRule{{Action: "accept", Src: []string{"a"}, Ports: []string{"*"}}}},
		"missing src":               {ACLs: []ACLRule{{Action: "accept", Dst: []string{"a"}, Ports: []string{"*"}}}},
		"undefined group":           {ACLs: []ACLRule{{Action: "accept", Src: []string{"group:nope"}, Dst: []string{"*"}, Ports: []string{"*"}}}},
		"empty tag selector":        {ACLs: []ACLRule{{Action: "accept", Src: []string{"tag:"}, Dst: []string{"*"}, Ports: []string{"*"}}}},
		"group name no prefix": {Groups: map[string][]string{"ops": {"a"}},
			ACLs: []ACLRule{{Action: "accept", Src: []string{"*"}, Dst: []string{"*"}, Ports: []string{"*"}}}},
		"nested group member": {Groups: map[string][]string{"group:a": {"group:b"}, "group:b": {"x"}},
			ACLs: []ACLRule{{Action: "accept", Src: []string{"group:a"}, Dst: []string{"*"}, Ports: []string{"*"}}}},

		// The split: selectors name machines, ports are a field. A rule with no
		// ports is the legacy shape — readable, never writable, because saving it
		// would mean the admin's ports live somewhere the editor no longer shows.
		"no ports (legacy shape)": {ACLs: []ACLRule{{Action: "accept", Src: []string{"*"}, Dst: []string{"tag:db:5432"}}}},
		"port glued onto dst": {ACLs: []ACLRule{{Action: "accept", Src: []string{"*"},
			Dst: []string{"tag:db:5432"}, Ports: []string{"*"}}}},
		"svc: as a dst selector": {ACLs: []ACLRule{{Action: "accept", Src: []string{"*"},
			Dst: []string{"svc:web"}, Ports: []string{"*"}}}},
		"svc: as a src selector": {ACLs: []ACLRule{{Action: "accept", Src: []string{"svc:web"},
			Dst: []string{"*"}, Ports: []string{"*"}}}},
		"port on a src selector": {ACLs: []ACLRule{{Action: "accept", Src: []string{"laptop:22"},
			Dst: []string{"*"}, Ports: []string{"*"}}}},
		"unparseable port": {ACLs: []ACLRule{{Action: "accept", Src: []string{"*"},
			Dst: []string{"*"}, Ports: []string{"http"}}}},
		"port zero": {ACLs: []ACLRule{{Action: "accept", Src: []string{"*"},
			Dst: []string{"*"}, Ports: []string{"0"}}}},
		"backwards range": {ACLs: []ACLRule{{Action: "accept", Src: []string{"*"},
			Dst: []string{"*"}, Ports: []string{"900-800"}}}},
		"empty service port": {ACLs: []ACLRule{{Action: "accept", Src: []string{"*"},
			Dst: []string{"*"}, Ports: []string{"svc:"}}}},
	}
	for name, p := range bad {
		if err := ValidateACLPolicy(p); err == nil {
			t.Fatalf("invalid doc %q was accepted", name)
		}
	}
}
