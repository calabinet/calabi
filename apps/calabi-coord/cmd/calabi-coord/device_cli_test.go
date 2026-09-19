package main

import (
	"context"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/calabi/calabi/apps/calabi-coord/internal/adminhttp"
	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
)

// `calabi-coord device` against a running coordinator's admin API: the list
// shows each device's state, and approve / disable / enable / delete change the
// device they name, in the meshnet asked for.
func TestDeviceCommands(t *testing.T) {
	ctx := context.Background()
	nodes := core.NewMemNodeStore()
	coord := &core.Coordinator{Nodes: nodes, AuthKeys: core.NewMemAuthKeyStore(), Logger: quietLogger()}
	srv := httptest.NewServer(adminhttp.New(coord, core.NewNotifier(), quietLogger()))
	defer srv.Close()
	laptop, _ := nodes.Upsert(ctx, &core.Node{Meshnet: 1, Name: "laptop", OS: "linux", Approved: true,
		Overlay: netip.MustParseAddr("100.64.0.1")})
	phone, _ := nodes.Upsert(ctx, &core.Node{Meshnet: 1, Name: "phone", OS: "android",
		Overlay: netip.MustParseAddr("100.64.0.2")})
	other, _ := nodes.Upsert(ctx, &core.Node{Meshnet: 2, Name: "elsewhere", Approved: true})

	admin := []string{"--admin", srv.URL, "--token", "t"}
	run := func(args ...string) (string, int) {
		return captureStdout(t, func() int { return runDevice(append(args, admin...)) })
	}
	id := func(n *core.Node) string { return strconv.FormatInt(n.ID, 10) }

	out, code := run("list")
	if code != 0 || !strings.Contains(out, "laptop") || !strings.Contains(out, "100.64.0.1") ||
		!strings.Contains(out, "waiting for approval") || strings.Contains(out, "elsewhere") {
		t.Fatalf("device list (exit %d):\n%s", code, out)
	}

	if _, code := captureStdout(t, func() int { return runDevice(append([]string{"approve"}, append(admin, id(phone))...)) }); code != 0 {
		t.Fatalf("approve: exit %d", code)
	}
	if n, _ := nodes.Get(ctx, phone.ID); !n.Approved {
		t.Fatal("approve did not approve the device")
	}
	if _, code := captureStdout(t, func() int { return runDevice(append([]string{"disable"}, append(admin, id(laptop))...)) }); code != 0 {
		t.Fatalf("disable: exit %d", code)
	}
	if n, _ := nodes.Get(ctx, laptop.ID); !n.Disabled {
		t.Fatal("disable did not disable the device")
	}
	if out, _ := run("list"); !strings.Contains(out, "disabled") {
		t.Fatalf("list after disable:\n%s", out)
	}
	if _, code := captureStdout(t, func() int { return runDevice(append([]string{"enable"}, append(admin, id(laptop))...)) }); code != 0 {
		t.Fatalf("enable: exit %d", code)
	}
	if n, _ := nodes.Get(ctx, laptop.ID); n.Disabled {
		t.Fatal("enable did not enable the device")
	}
	if _, code := captureStdout(t, func() int { return runDevice(append([]string{"delete"}, append(admin, id(phone))...)) }); code != 0 {
		t.Fatalf("delete: exit %d", code)
	}
	if n, err := nodes.Get(ctx, phone.ID); err == nil && n != nil {
		t.Fatal("delete left the device in place")
	}
	// A device of another meshnet is not this one's to delete.
	if _, code := captureStdout(t, func() int { return runDevice(append([]string{"delete"}, append(admin, id(other))...)) }); code == 0 {
		t.Fatal("deleted a device of another meshnet")
	}
	if n, err := nodes.Get(ctx, other.ID); err != nil || n == nil {
		t.Fatal("the other meshnet's device is gone")
	}

	if _, code := run("reboot"); code != 2 {
		t.Fatalf("an unknown command: exit %d, want 2", code)
	}
	if _, code := captureStdout(t, func() int { return runDevice(append([]string{"disable"}, admin...)) }); code != 2 {
		t.Fatalf("disable without an id: exit %d, want 2", code)
	}
}
