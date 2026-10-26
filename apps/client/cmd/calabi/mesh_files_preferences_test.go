package main

import (
	"context"
	"errors"
	"github.com/calabinet/calabi/apps/client/internal/filecontrol"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	"github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDesktopMetadataPollingContinuesDuringSaveDialog(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("ordinary user fixture")
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("APPDATA", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var reads atomic.Int64
	key := meshproto.NodeKey{1}
	console := "http://127.0.0.1:17449"
	ctl := &filecontrol.Control{Source: filecontrol.Source{View: func() (filecontrol.Snapshot, error) {
		reads.Add(1)
		return filecontrol.Snapshot{Ready: true, Scope: "save-dialog/org", NodeKey: key.String(), Overlay: "127.0.0.1"}, nil
	}}}
	done, err := filecontrol.Serve(ctx, ctl, console)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); <-done }()
	d, err := newDesktopFileAgent(ctx, console)
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	d.opMu.Lock() // Same lock held throughout a native save panel and export.
	defer d.opMu.Unlock()
	before := reads.Load()
	deadline := time.Now().Add(4500 * time.Millisecond)
	for reads.Load() < before+3 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if reads.Load() < before+3 {
		t.Fatalf("save dialog blocked metadata polling: %d refreshes", reads.Load()-before)
	}
	if _, err := d.metadata(); err != nil {
		t.Fatalf("live metadata expired during save dialog: %v", err)
	}
}

func TestDesktopReceptionSurvivesRestartButNotAuthBoundary(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("ordinary user fixture")
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("APPDATA", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var epoch atomic.Int64
	var offline atomic.Bool
	key := meshproto.NodeKey{1}
	console := "http://127.0.0.1:17439"
	ctl := &filecontrol.Control{Source: filecontrol.Source{View: func() (filecontrol.Snapshot, error) {
		if offline.Load() {
			return filecontrol.Snapshot{}, errors.New("temporarily offline")
		}
		return filecontrol.Snapshot{Ready: true, Scope: "test/org7", NodeKey: key.String(), Overlay: netip.MustParseAddr("127.0.0.1").String(), ReceiveEpoch: epoch.Load()}, nil
	}, Publish: func(context.Context, string, *meshpb.FileTransferInfo) error { return nil }}}
	done, err := filecontrol.Serve(ctx, ctl, console)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); <-done }()
	directory := ""
	open := func() *desktopFileAgent {
		d, err := newDesktopFileAgent(ctx, console)
		if err != nil {
			t.Fatal(err)
		}
		if err = d.configureManaged(directory); err != nil {
			t.Fatal(err)
		}
		d.reconcileManaged()
		return d
	}
	d := open()
	if status := d.managedSnapshot(); status["managed"] != false || status["persistent"] != true {
		t.Fatalf("desktop preference exposed Linux service controls: %#v", status)
	}
	if d.managed.settings.Receiving || d.w.Agent.Receiving() {
		t.Fatal("first use enabled reception")
	}
	if _, err = d.handle(fileAction{Action: "receiving", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	d.close()
	d = open()
	defer func() { d.close() }()
	if !d.managed.settings.Receiving || !d.w.Agent.Receiving() {
		t.Fatal("explicit choice lost on restart")
	}
	offline.Store(true)
	d.poll()
	d.reconcileManaged()
	if !d.managed.settings.Receiving || d.w.Agent.Receiving() {
		t.Fatal("offline state confused with saved choice")
	}
	if _, err = d.handle(fileAction{Action: "receiving", Enabled: false}); err != nil {
		t.Fatal(err)
	}
	d.close()
	offline.Store(false)
	d = open()
	if d.managed.settings.Receiving || d.w.Agent.Receiving() {
		t.Fatal("disabled reception came back after restart")
	}
	if _, err = d.handle(fileAction{Action: "receiving", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	epoch.Add(1)
	d.poll()
	d.reconcileManaged()
	if d.managed.settings.Receiving || d.w.Agent.Receiving() {
		t.Fatal("logout/org boundary retained reception")
	}
	b, err := os.ReadFile(filepath.Join(d.dir, "receive-settings.json"))
	if err != nil || !strings.Contains(string(b), `"receiving":false`) {
		t.Fatalf("choice not persisted: %v %s", err, b)
	}
}
