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
