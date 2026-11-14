package filecontrol

import "testing"

func TestRDPLoginPermissionDoesNotInventOwnership(t *testing.T) {
	member := Member{OS: "windows", RDPAccessAllowed: true}
	if !member.CanRDPLogin() || member.SameOwner || member.OwnWindows {
		t.Fatal("self-hosted grant should authorize RDP without ownership")
	}
	member.RDPAccessAllowed = false
	if member.CanRDPLogin() {
		t.Fatal("unattributed Windows authorized without grant")
	}
	member.RDPAccessAllowed = true
	member.OS = "linux"
	if member.CanRDPLogin() {
		t.Fatal("non-Windows device offered as RDP target")
	}
	if !(Member{OwnWindows: true}).CanRDPLogin() {
		t.Fatal("old service metadata lost compatibility")
	}
}
