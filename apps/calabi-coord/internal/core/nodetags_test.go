package core

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

// Tags are normalized the same way selectors are, because that is what they
// become: a tag nobody can type consistently is a rule that silently matches
// nothing.
func TestNormalizeNodeTags(t *testing.T) {
	got, err := NormalizeNodeTags([]string{" TAG:Server ", "tag:db", "tag:server", ""})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if want := []string{"tag:server", "tag:db"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v (lowercased, de-duplicated, order kept)", got, want)
	}

	for _, bad := range []string{"server", "tag:", "tag:has space", "tag:UPPER!", "tag:-lead"} {
		if _, err := NormalizeNodeTags([]string{bad}); !errors.Is(err, ErrInvalidNodeTag) {
			t.Errorf("NormalizeNodeTags(%q) err = %v, want ErrInvalidNodeTag", bad, err)
		}
	}
}

// The whole point of pinning: on the platform build the identity service
// carries NO tags, so without it every daemon restart would wipe what an admin
// set. Same trap NamePinned exists for.
func TestSetNodeTagsSurvivesReRegistration(t *testing.T) {
	c := newTestCoord()
	ctx := context.Background()
	node, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "web", NodeKey: key(1)})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	if _, err := c.SetNodeTags(ctx, 1, node.ID, []string{"tag:server"}); err != nil {
		t.Fatalf("set tags: %v", err)
	}

	// The daemon reconnects, carrying no tags at all (the platform case).
	again, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "web", NodeKey: key(1)})
	if err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if !reflect.DeepEqual(again.Tags, []string{"tag:server"}) {
		t.Fatalf("tags after re-registration = %v, want [tag:server]", again.Tags)
	}
	if !again.TagsPinned {
		t.Error("TagsPinned was lost")
	}
}

// Until an admin sets them, tags still come from the auth key — the community
// coordinator's behaviour must not change.
func TestUnpinnedTagsStillFollowTheAuthKey(t *testing.T) {
	c := newTestCoord()
	ctx := context.Background()
	if _, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "web", NodeKey: key(1), Tags: []string{"tag:a"}}); err != nil {
		t.Fatalf("register: %v", err)
	}
	again, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "web", NodeKey: key(1), Tags: []string{"tag:b"}})
	if err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if !reflect.DeepEqual(again.Tags, []string{"tag:b"}) {
		t.Fatalf("tags = %v, want [tag:b] (the key is still authoritative until pinned)", again.Tags)
	}
}

// A tag grants access, so setting one on another tenant's node must 404 rather
// than work.
func TestSetNodeTagsTenantBoundary(t *testing.T) {
	c := newTestCoord()
	ctx := context.Background()
	theirs, _ := c.Register(ctx, RegisterInput{Meshnet: 2, Name: "theirs", NodeKey: key(2)})

	if _, err := c.SetNodeTags(ctx, 1, theirs.ID, []string{"tag:mine"}); !errors.Is(err, ErrNodeNotFound) {
		t.Fatalf("cross-tenant set tags err = %v, want ErrNodeNotFound", err)
	}
	got, _ := c.Nodes.Get(ctx, theirs.ID)
	if len(got.Tags) != 0 {
		t.Fatalf("another meshnet's node was tagged: %v", got.Tags)
	}
}

// BOTH sides of a rule are sets of MACHINES. A port belongs in the rule's ports
// field (the compiler turns selectors into CIDRs and never reads a port off
// one), and a service name is picked per-device and unique only within it — so
// letting it select machines would let an unprivileged declaration widen an
// existing rule. Neither spelling may be stored on either side.
func TestSelectorsNameMachinesOnly(t *testing.T) {
	bad := []string{"laptop:22", "tag:laptop:22", "svc:web", "svc:web:443"}
	for _, s := range bad {
		src := ACLPolicy{ACLs: []ACLRule{{Action: "accept", Src: []string{s}, Dst: []string{"*"}, Ports: []string{"*"}}}}
		if err := ValidateACLPolicy(src); err == nil {
			t.Errorf("src selector %q was accepted; it must be refused", s)
		}
		dst := ACLPolicy{ACLs: []ACLRule{{Action: "accept", Src: []string{"*"}, Dst: []string{s}, Ports: []string{"*"}}}}
		if err := ValidateACLPolicy(dst); err == nil {
			t.Errorf("dst selector %q was accepted; it must be refused", s)
		}
	}
	// What replaces them: machines by tag, the port as a field.
	okDoc := ACLPolicy{ACLs: []ACLRule{{Action: "accept",
		Src: []string{"tag:laptop"}, Dst: []string{"tag:server"}, Ports: []string{"22", "svc:web"}}}}
	if err := ValidateACLPolicy(okDoc); err != nil {
		t.Errorf("the replacement spelling was refused: %v", err)
	}
}
