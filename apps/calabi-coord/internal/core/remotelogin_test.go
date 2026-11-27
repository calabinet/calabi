package core

import (
	"slices"
	"testing"
)

func TestRemoteLoginRequiresExplicitDestinationPortAndDirection(t *testing.T) {
	mac := &Node{ID: 1, Name: "mac", OS: "darwin", OwnerUserID: 1, Approved: true}
	second := &Node{ID: 5, Name: "laptop", OS: "linux", OwnerUserID: 1, Approved: true}
	other := &Node{ID: 6, Name: "other", OS: "darwin", OwnerUserID: 3, Approved: true, Tags: []string{"tag:operator"}}
	windows := &Node{ID: 2, Name: "windows", OS: "windows", OwnerUserID: 2, Approved: true}
	linux := &Node{ID: 3, Name: "linux", OS: "linux", OwnerUserID: 2, Approved: true,
		Services: []Service{{Name: "ssh", Proto: "tcp", Port: 2222}}}
	doc := &ACLPolicy{Groups: map[string][]string{"group:operators": {"user:1", "tag:operator", "device:6"}}, ACLs: []ACLRule{
		{Action: "accept", Src: []string{"*"}, Dst: []string{"*"}, Ports: []string{"*"}},
		{Action: "accept", Src: []string{"mac"}, Dst: []string{"*"}, Ports: []string{"tcp:22"}},
		{Action: "accept", Src: []string{"mac"}, Dst: []string{"linux"}, Ports: []string{"tcp:22"}},
		{Action: "accept", Src: []string{"device:1", "device:6", "autogroup:member"}, Dst: []string{"device:3"}, Ports: []string{"tcp:22"}},
		{Action: "accept", Src: []string{"user:1"}, Dst: []string{"device:3"}, Ports: []string{"tcp:1-100", "tcp:2222", "tcp:2223"}},
		{Action: "accept", Src: []string{"group:operators"}, Dst: []string{"device:2"}, Ports: []string{"tcp:3389"}},
	}}
	if err := ValidateACLPolicy(*doc); err != nil {
		t.Fatalf("the editor's device rules must be valid: %v", err)
	}
	got := remoteLoginFor(mac, []*Node{linux, windows}, doc)
	if !slices.Equal(got[linux.ID].ToPeer, []uint32{2222}) ||
		!slices.Equal(got[windows.ID].ToPeer, []uint32{3389}) ||
		len(got[linux.ID].FromPeer)+len(got[windows.ID].FromPeer) != 0 {
		t.Fatalf("outbound grants = %+v", got)
	}
	for _, source := range []*Node{second, other, {ID: 7, Approved: true}} {
		got := remoteLoginFor(source, []*Node{linux, windows}, doc)
		if source == second {
			if !slices.Equal(got[linux.ID].ToPeer, []uint32{2222}) || !slices.Equal(got[windows.ID].ToPeer, []uint32{3389}) {
				t.Fatalf("the account's second device lost its grants: %+v", got)
			}
		} else if len(got) != 0 {
			t.Fatalf("device or tag granted login to another identity: %+v", got)
		}
	}
	got = remoteLoginFor(windows, []*Node{mac, linux, second, other}, doc)
	if !slices.Equal(got[mac.ID].FromPeer, []uint32{3389}) || !slices.Equal(got[second.ID].FromPeer, []uint32{3389}) ||
		len(got[mac.ID].ToPeer) != 0 || len(got[other.ID].FromPeer) != 0 {
		t.Fatalf("inbound grants = %+v", got)
	}
	windows.Name = "renamed"
	if got := remoteLoginFor(mac, []*Node{windows, {ID: 4, Name: "windows", OS: "windows", OwnerUserID: 2, Approved: true}}, doc); len(got) != 1 || len(got[windows.ID].ToPeer) == 0 {
		t.Fatalf("grant did not stay with the selected device: %+v", got)
	}
	doc.ACLs = append(doc.ACLs, ACLRule{Action: "deny", Src: []string{"user:1"}, Dst: []string{"device:2"}, Ports: []string{"tcp:3389"}})
	if got := remoteLoginFor(windows, []*Node{mac, second}, doc); len(got) != 0 {
		t.Fatalf("deny failed to revoke login: %+v", got)
	}
}
