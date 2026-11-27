package main

import (
	"context"
	"github.com/calabinet/calabi/apps/client/internal/filecontrol"
	"github.com/calabinet/calabi/apps/client/internal/filetransfer"
	"net/netip"
	"testing"
	"time"
)

func TestClipboardPeerOwnedMac(t *testing.T) {
	d := &desktopFileAgent{ctx: context.Background(), updated: time.Now(), view: filecontrol.Snapshot{Ready: true, Overlay: "100.64.0.36", Members: []filecontrol.Member{{IP: "100.64.0.18", DeviceKey: "mac", SameOwner: true}}}}
	d.shellPasteLive.Store(true)
	g := filetransfer.Grant{DeviceKey: "mac", Peer: filetransfer.Peer{IP: netip.MustParseAddr("100.64.0.18")}}
	if !d.clipboardPeer(g) {
		t.Fatal("owned Mac should be allowed")
	}
	d.view.Members[0].SameOwner = false
	if d.clipboardPeer(g) {
		t.Fatal("other owner accepted")
	}
	d.view.Members[0].SameOwner = true
	g.DeviceKey = "another-device"
	if d.clipboardPeer(g) {
		t.Fatal("wrong key accepted")
	}
	g.DeviceKey = "mac"
	g.Peer.IP = netip.MustParseAddr("100.64.0.19")
	if d.clipboardPeer(g) {
		t.Fatal("wrong IP accepted")
	}
	g.Peer.IP = netip.MustParseAddr("100.64.0.18")
	d.updated = time.Now().Add(-3 * time.Second)
	if d.clipboardPeer(g) {
		t.Fatal("expired metadata accepted")
	}
	d.updated = time.Now()
	d.shellPasteLive.Store(false)
	if d.clipboardPeer(g) {
		t.Fatal("disabled adapter accepted")
	}
}

func TestClipboardPeerSelfHostedRDPDoesNotGrantFileAccess(t *testing.T) {
	d := &desktopFileAgent{ctx: context.Background(), updated: time.Now(), view: filecontrol.Snapshot{Ready: true, Overlay: "100.64.0.36", Members: []filecontrol.Member{{IP: "100.64.0.18", DeviceKey: "mac", RDPAccessAllowed: true}}}}
	d.shellPasteLive.Store(true)
	grant := filetransfer.Grant{DeviceKey: "mac", Peer: filetransfer.Peer{IP: netip.MustParseAddr("100.64.0.18")}}
	if d.clipboardPeer(grant) {
		t.Fatal("RDP network permission granted owner-only clipboard-file access")
	}
	d.view.Members[0].SameOwner = true
	if !d.clipboardPeer(grant) {
		t.Fatal("existing same-owner clipboard permission lost")
	}
	d.shellPasteLive.Store(false)
	if d.clipboardPeer(grant) {
		t.Fatal("clipboard switch bypassed")
	}
}

func TestRDPCopyPermissionUsesDirectionAndPort(t *testing.T) {
	windows := filecontrol.Member{OS: "windows", RemoteLoginPorts: []uint16{3389}}
	mac := filecontrol.Member{OS: "darwin", IncomingRemoteLoginPorts: []uint16{3389}}
	for _, test := range []struct {
		member filecontrol.Member
		host   bool
		port   uint16
		want   bool
	}{
		{windows, false, 3389, true},
		{windows, true, 3389, false},
		{windows, false, 3390, false},
		{windows, false, 0, false},
		{mac, true, 3389, true},
		{mac, false, 3389, false},
	} {
		if allowed, bind := permitsRDPCopy(test.member, test.host, test.port); allowed != test.want || bind != test.want {
			t.Fatalf("permission for %s, host=%t, port=%d: allowed=%t, bind=%t", test.member.OS, test.host, test.port, allowed, bind)
		}
	}
	if allowed, bind := permitsRDPCopy(filecontrol.Member{OS: "windows", OwnWindows: true}, false, 0); !allowed || bind {
		t.Fatal("older same-owner desktop lost clipboard access")
	}
}
