package core

import (
	"context"
	"errors"
	"slices"
	"testing"
)

func TestExplicitDenyPreviewAndSaveGate(t *testing.T) {
	ctx := context.Background()
	c := newTestCoord()
	store := NewMemACLStore()
	c.ACL = store
	source := RegisterInput{Meshnet: 1, Name: "a", NodeKey: key(1)}
	receiver := RegisterInput{Meshnet: 1, Name: "b", NodeKey: key(2)}
	for _, input := range []RegisterInput{source, receiver} {
		if _, err := c.Register(ctx, input); err != nil {
			t.Fatal(err)
		}
	}
	doc := allowAllDoc()
	doc.ACLs = append(doc.ACLs, ACLRule{
		Action: "deny", Src: []string{"a"}, Dst: []string{"b"}, Ports: []string{"tcp:22"},
	})
	want := []AccessChange{{Src: "a", Dst: "b", PortRange: PortRange{First: 22, Last: 22, Proto: "tcp"}}}
	preview := func(blockers []string) {
		t.Helper()
		got, err := c.PreviewACL(ctx, 1, doc)
		if err != nil {
			t.Fatal(err)
		}
		if !got.FirstConfiguration || got.Baseline != "allow_all" || !slices.Equal(got.IncompatibleDevices, blockers) ||
			!slices.Equal(got.Traffic.Removed, want) || got.Traffic.AddedCount != 0 {
			t.Fatalf("preview = %+v, traffic = %+v", got, got.Traffic)
		}
	}
	preview([]string{"b"})
	if err := c.SaveACL(ctx, 1, doc, ""); !errors.Is(err, ErrInvalidACL) {
		t.Fatalf("old receiver save = %v", err)
	}
	if _, exists, err := store.GetACL(ctx, 1); exists || err != nil {
		t.Fatalf("blocked policy persisted: exists=%v err=%v", exists, err)
	}
	receiver.ACLPortless = true
	if _, err := c.Register(ctx, receiver); err != nil {
		t.Fatal(err)
	}
	preview(nil)
	for _, index := range []int{1, 0} {
		for _, check := range []struct {
			src, dst, proto string
			allowed         bool
		}{{"a", "b", "tcp", false}, {"a", "b", "udp", true}, {"b", "a", "tcp", true}} {
			got, err := c.CheckPortAccess(ctx, 1, check.src, check.dst, &doc, check.proto, 22)
			if err != nil || got.Transport == nil || got.Transport.Allowed != check.allowed {
				t.Fatalf("check %+v = %+v, %v", check, got.Transport, err)
			}
			if !check.allowed && (got.Transport.Reason != "explicit_deny" || got.Transport.Rule != index) {
				t.Fatalf("deny explanation = %+v, want rule %d", got.Transport, index)
			}
		}
		slices.Reverse(doc.ACLs)
	}
	if err := c.SaveACL(ctx, 1, doc, ""); err != nil {
		t.Fatal(err)
	}
	receiver.ACLPortless = false
	if _, err := c.Register(ctx, receiver); err != nil {
		t.Fatal(err)
	}
	doc.ACLs[0].Ports = []string{"tcp:*", "udp:*"}
	if err := c.SaveACL(ctx, 1, doc, ""); err != nil {
		t.Fatalf("TCP/UDP-only policy should compile for older receivers: %v", err)
	}
}

func TestICMPAccessPreviewAndSave(t *testing.T) {
	ctx := context.Background()
	c := newTestCoord()
	c.ACL = NewMemACLStore()
	receiver := RegisterInput{Meshnet: 1, Name: "b", NodeKey: key(2), ACLPortless: true}
	for _, input := range []RegisterInput{{Meshnet: 1, Name: "a", NodeKey: key(1)}, receiver} {
		if _, err := c.Register(ctx, input); err != nil {
			t.Fatal(err)
		}
	}
	doc := allowAllDoc()
	doc.ACLs = append(doc.ACLs, ACLRule{Action: "deny", Src: []string{"a"}, Dst: []string{"b"}, Ports: []string{"icmp"}})
	preview, err := c.PreviewACL(ctx, 1, doc)
	want := []AccessChange{{Src: "a", Dst: "b", PortRange: PortRange{Proto: "icmp"}}}
	if err != nil || preview.Traffic == nil || !slices.Equal(preview.Traffic.Removed, want) ||
		preview.Traffic.AddedCount != 0 || !slices.Equal(preview.IncompatibleDevices, []string{"b"}) {
		t.Fatalf("ICMP preview = %+v, traffic = %+v, err = %v", preview, preview.Traffic, err)
	}
	allowOnly := ACLPolicy{ACLs: []ACLRule{{Action: "accept", Src: []string{"a"}, Dst: []string{"b"}, Ports: []string{"icmp"}}}}
	for _, policy := range []ACLPolicy{doc, allowOnly} {
		if err := c.SaveACL(ctx, 1, policy, ""); !errors.Is(err, ErrInvalidACL) {
			t.Fatalf("pre-ICMP receiver could save %+v: %v", policy, err)
		}
	}
	receiver.ACLICMP = true
	if _, err := c.Register(ctx, receiver); err != nil {
		t.Fatal(err)
	}
	if err := c.SaveACL(ctx, 1, doc, ""); err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		src, dst, proto string
		port            int
		reason          string
	}{
		{"a", "b", "icmp", 0, "explicit_deny"},
		{"a", "b", "tcp", 22, "rule"},
		{"a", "b", "udp", 22, "rule"},
		{"b", "a", "icmp", 0, "rule"},
	} {
		got, err := c.CheckPortAccess(ctx, 1, check.src, check.dst, nil, check.proto, check.port)
		if err != nil || got.Transport == nil || got.Transport.Reason != check.reason ||
			got.Transport.Allowed != (check.reason == "rule") {
			t.Fatalf("check %+v = %+v, %v", check, got.Transport, err)
		}
	}
	if _, err := c.CheckPortAccess(ctx, 1, "a", "b", nil, "icmp", 22); !errors.Is(err, ErrInvalidAccessPort) {
		t.Fatalf("ICMP with a port = %v", err)
	}
	for _, spec := range []string{"tcp:*", "1-65535", "*"} {
		doc.ACLs[1].Ports = []string{spec}
		got, err := c.CheckPortAccess(ctx, 1, "a", "b", &doc, "icmp", 0)
		if err != nil || got.Transport == nil || got.Transport.Allowed != (spec != "*") {
			t.Fatalf("deny %q against ICMP = %+v, %v", spec, got.Transport, err)
		}
	}
}
