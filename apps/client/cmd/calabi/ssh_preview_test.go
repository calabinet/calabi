package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/calabinet/calabi/apps/client/internal/filecontrol"
)

func TestSSHPreviewFitsAgentPipe(t *testing.T) {
	var input, output bytes.Buffer
	encoder := json.NewEncoder(&input)
	_ = encoder.Encode(fileAction{Action: "ssh_preview", SSHPreview: strings.Repeat("00", 2+192*108*4)})
	_ = encoder.Encode(fileAction{Action: "snapshot"})
	_ = encoder.Encode(fileAction{Action: "ssh_record", RDPName: strings.Repeat("a", 20000)})
	var called []string
	if serveFileActions(&input, &output, func(a fileAction) (any, error) { called = append(called, a.Action); return nil, nil }) != 0 {
		t.Fatal("preview broke pipe")
	}
	if strings.Join(called, ",") != "ssh_preview,snapshot" {
		t.Fatalf("ordinary action limit changed: %v", called)
	}
}

func TestSSHPreviewAuthorizationAndLoginIsolation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	view := filecontrol.Snapshot{Ready: true, AccountID: 31, Scope: "ssh-preview-test", Overlay: "100.64.0.1", Members: []filecontrol.Member{{DeviceKey: "linux", IP: "100.64.0.2", OS: "linux"}}}
	ctl := &filecontrol.Control{Source: filecontrol.Source{View: func() (filecontrol.Snapshot, error) { mu.Lock(); defer mu.Unlock(); return view, nil }}}
	console := fmt.Sprintf("http://127.0.0.1:%d", 31000+os.Getpid()%10000)
	done, err := filecontrol.Serve(ctx, ctl, console)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); <-done }()
	d := &desktopFileAgent{ctx: ctx, console: console, dir: t.TempDir()}
	profile := rdpProfile(view)
	preview := fileAction{Action: "ssh_preview", Peer: "linux", RDPProfile: profile, RDPAccount: "alice", SSHPort: 22, SSHPreview: "0101ff0000ff"}
	if _, err := d.sshAction(preview); err == nil {
		t.Fatal("accepted thumbnail before login")
	}
	for _, login := range []struct {
		account string
		port    uint16
	}{{"alice", 22}, {"bob", 22}, {"alice", 2222}} {
		if _, err := d.sshAction(fileAction{Action: "ssh_record", Peer: "linux", RDPProfile: profile, RDPAccount: login.account, SSHPort: login.port}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.sshAction(preview); err != nil {
		t.Fatal(err)
	}
	history, err := d.sshAction(fileAction{Action: "ssh_history"})
	if err != nil {
		t.Fatal(err)
	}
	records := history.(map[string]any)["records"].([]remoteRecent)
	for _, r := range records {
		if (r.Thumbnail != "") != (r.Account == "alice" && r.Port == 22) {
			t.Fatalf("preview crossed login boundary: %#v", r)
		}
	}
	// Reconnecting the same login retains its last valid image.
	if _, err := d.sshAction(fileAction{Action: "ssh_record", Peer: "linux", RDPProfile: profile, RDPAccount: "alice", SSHPort: 22}); err != nil {
		t.Fatal(err)
	}
	good := readRDPPreview(d.dir, "ssh-"+profile, sshPreviewID(remoteRecent{Peer: "linux", Account: "alice", Port: 22}))
	preview.SSHPreview = "not hex"
	if _, err := d.sshAction(preview); err == nil {
		t.Fatal("accepted invalid image")
	}
	if readRDPPreview(d.dir, "ssh-"+profile, sshPreviewID(remoteRecent{Peer: "linux", Account: "alice", Port: 22})) != good {
		t.Fatal("invalid image replaced preview")
	}
	preview.SSHPreview = "010100ff00ff"
	for _, change := range []func(){func() { view.AccountID++ }, func() { view.Scope = "different" }, func() { view.Ready = false }, func() { view.Members = nil }, func() { view.Members = []filecontrol.Member{{DeviceKey: "linux", IP: "100.64.0.2", OS: "windows"}} }} {
		mu.Lock()
		saved := view
		change()
		mu.Unlock()
		if _, err := d.sshAction(preview); err == nil {
			t.Fatal("accepted stale target or identity")
		}
		mu.Lock()
		view = saved
		mu.Unlock()
	}
	// Evicting a login also removes only its own preview.
	for n := 0; n < 32; n++ {
		if _, err := d.sshAction(fileAction{Action: "ssh_record", Peer: "linux", RDPProfile: profile, RDPAccount: fmt.Sprintf("user%d", n), SSHPort: 22}); err != nil {
			t.Fatal(err)
		}
	}
	if readRDPPreview(d.dir, "ssh-"+profile, sshPreviewID(remoteRecent{Peer: "linux", Account: "alice", Port: 22})) != "" {
		t.Fatal("evicted preview leaked")
	}
}
