package main

import (
	"slices"
	"testing"

	"github.com/calabinet/calabi/apps/client/internal/filecontrol"
)

func TestSSHTargetUsesCurrentLinuxDeviceAndProfile(t *testing.T) {
	view := filecontrol.Snapshot{
		Ready: true, AccountID: 42, Scope: "test-network", Overlay: "100.64.0.1",
		Members: []filecontrol.Member{
			{DeviceKey: "linux", IP: "100.64.0.2", OS: "linux", SameOwner: true},
			{DeviceKey: "windows", IP: "100.64.0.3", OS: "windows", SameOwner: true},
			{DeviceKey: "outside", IP: "192.168.0.4", OS: "linux", SameOwner: true},
			{DeviceKey: "self", IP: "100.64.0.1", OS: "linux", SameOwner: true},
			{DeviceKey: "other-member", IP: "100.64.0.5", OS: "linux"},
		},
	}
	target, err := sshTarget(view, "linux")
	if err != nil || target["host"] != "100.64.0.2" || target["local"] != "100.64.0.1" {
		t.Fatalf("target = %v, %v", target, err)
	}
	if keys := sshTargetKeys(view); !slices.Equal(keys, []string{"linux"}) {
		t.Fatalf("SSH device menu targets = %v", keys)
	}
	view.Members[4].RemoteLoginPorts = []uint16{2222}
	if target, err := sshLoginTarget(view, "other-member", 2222); err != nil || target["ports"] != "2222" {
		t.Fatalf("delegated SSH target = %v, %v", target, err)
	}
	if _, err := sshLoginTarget(view, "other-member", 22); err == nil {
		t.Fatal("delegated target accepted an ungranted port")
	}
	view.Members[4].RemoteLoginPorts = nil
	for _, peer := range []string{"windows", "outside", "self", "other-member", "unknown", ""} {
		if _, err := sshTarget(view, peer); err == nil {
			t.Errorf("accepted invalid target %q", peer)
		}
	}
	view.AccountID++
	other, err := sshTarget(view, "linux")
	if err != nil || other["profile"] == target["profile"] || other["host_key"] == target["host_key"] {
		t.Fatalf("account reused an SSH trust profile: %v, %v", other, err)
	}
	view.Ready = false
	if keys := sshTargetKeys(view); len(keys) != 0 {
		t.Fatalf("disconnected device menu exposed SSH targets: %v", keys)
	}
	if _, err := sshTarget(view, "linux"); err == nil {
		t.Fatal("disconnected mesh accepted an SSH target")
	}
}
