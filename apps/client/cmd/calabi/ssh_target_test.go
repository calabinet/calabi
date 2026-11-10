package main

import (
	"testing"

	"github.com/calabinet/calabi/apps/client/internal/filecontrol"
)

func TestSSHTargetUsesCurrentLinuxDeviceAndProfile(t *testing.T) {
	view := filecontrol.Snapshot{
		Ready: true, AccountID: 42, Scope: "test-network", Overlay: "100.64.0.1",
		Members: []filecontrol.Member{
			{DeviceKey: "linux", IP: "100.64.0.2", OS: "linux"},
			{DeviceKey: "windows", IP: "100.64.0.3", OS: "windows"},
			{DeviceKey: "outside", IP: "192.168.0.4", OS: "linux"},
			{DeviceKey: "self", IP: "100.64.0.1", OS: "linux"},
		},
	}
	target, err := sshTarget(view, "linux")
	if err != nil || target["host"] != "100.64.0.2" || target["local"] != "100.64.0.1" {
		t.Fatalf("target = %v, %v", target, err)
	}
	for _, peer := range []string{"windows", "outside", "self", "unknown", ""} {
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
	if _, err := sshTarget(view, "linux"); err == nil {
		t.Fatal("disconnected mesh accepted an SSH target")
	}
}
