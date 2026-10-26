//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/calabinet/calabi/apps/client/internal/filecontrol"
	"github.com/calabinet/calabi/apps/client/internal/filetransfer"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	"github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
)

func TestManagedSaveRetriesWithoutOverwriteOrDuplicateAfterRestart(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("ordinary user fixture")
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	from, _ := filetransfer.NewIdentity()
	local := meshproto.NodeKey{1}
	remote := meshproto.NodeKey{2}
	console := "http://127.0.0.1:17429"
	ctl := &filecontrol.Control{Source: filecontrol.Source{View: func() (filecontrol.Snapshot, error) {
		return filecontrol.Snapshot{Ready: true, Scope: "save-test", NodeKey: local.String(), Overlay: "127.0.0.1", Peers: []filecontrol.Peer{{Grant: filetransfer.Grant{Peer: filetransfer.Peer{IP: netip.MustParseAddr("127.0.0.2"), Fingerprint: from.Fingerprint}, DeviceKey: remote.String(), Port: 17401}, Incoming: true, ExpiresUnix: time.Now().Add(time.Hour).Unix()}}, Members: []filecontrol.Member{{DeviceKey: remote.String(), IP: "127.0.0.2", Incoming: true}}}, nil
	}, Publish: func(context.Context, string, *meshpb.FileTransferInfo) error { return nil }}}
	done, err := filecontrol.Serve(ctx, ctl, console)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); <-done }()
	directory := t.TempDir()
	target := filepath.Join(directory, "test.bin")
	if err = os.WriteFile(target, []byte("keep original"), 0600); err != nil {
		t.Fatal(err)
	}
	open := func() *desktopFileAgent {
		d, e := newDesktopFileAgent(ctx, console)
		if e != nil {
			t.Fatal(e)
		}
		if e = d.configureManaged(directory); e != nil {
			t.Fatal(e)
		}
		d.reconcileManaged()
		return d
	}
	d := open()
	defer func() { d.close() }()
	if _, err = d.handle(fileAction{Action: "receiving", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err = d.handle(fileAction{Action: "service_settings", AutoSave: true}); err != nil {
		t.Fatal(err)
	}
	sender, err := filetransfer.NewWorkspace(filetransfer.AgentConfig{Identity: from, Directory: t.TempDir(), Scope: "sender", LocalIP: netip.MustParseAddr("127.0.0.2"), Port: 17401, Kbps: 32768, MaxBytes: 8 << 20, Resolve: func(netip.Addr) (filetransfer.Grant, bool) {
		return filetransfer.Grant{Peer: filetransfer.Peer{IP: netip.MustParseAddr("127.0.0.1"), Fingerprint: d.identity.Fingerprint}, DeviceKey: local.String(), Port: 17401, Receiving: true}, true
	}, Incoming: func(netip.Addr, uint16) bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	data := bytes.Repeat([]byte("verified bytes"), 100)
	source, err := sender.Stage(ctx, bytes.NewReader(data), "test.bin", int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = sender.Send(netip.MustParseAddr("127.0.0.1"), []string{source.ID}, ""); err != nil {
		t.Fatal(err)
	}
	wait := func(condition func() bool) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for !condition() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out; receiver=%#v jobs=%#v", d.w.Agent.List(), sender.Jobs())
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	wait(func() bool { return len(d.w.Agent.List()) == 1 })
	id := d.w.Agent.List()[0].Transfer.ID
	if _, err = d.handle(fileAction{Action: "decide", IDs: []string{id}, Accept: true}); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(directory, 0500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(directory, 0700)
	wait(func() bool { return d.w.Agent.List()[0].Transfer.State == "completed" })
	d.reconcileManaged()
	wait(func() bool { d.opMu.Lock(); defer d.opMu.Unlock(); return d.managed.saveError != "" })
	if err = os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	saved := filepath.Join(directory, "test (1).bin")
	wait(func() bool {
		d.reconcileManaged()
		d.opMu.Lock()
		defer d.opMu.Unlock()
		return d.managed.settings.Exported[id]
	})
	got, err := os.ReadFile(saved)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("save retry lost bytes: %v", err)
	}
	got, _ = os.ReadFile(target)
	if string(got) != "keep original" {
		t.Fatal("same-name file overwritten")
	}
	d.close()
	d = open()
	d.reconcileManaged()
	if _, err = os.Stat(filepath.Join(directory, "test (2).bin")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("restart duplicated auto-save")
	}
}

func TestManagedReceptionSurvivesRestartButNotAuthBoundary(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("ordinary user fixture")
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var epoch atomic.Int64
	var offline atomic.Bool
	key := meshproto.NodeKey{1}
	console := "http://127.0.0.1:17419"
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
	directory := t.TempDir()
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

func TestFileServiceUnitEscapesArgumentsAndSeparatesPrivileges(t *testing.T) {
	c := fileServiceConfig{Name: "calabi-files", User: "calabi-files", StateDir: "/var/lib/files with spaces", Directory: "/srv/files 50%", Console: "http://127.0.0.1:7500"}
	if err := validateFileServiceConfig(c); err != nil {
		t.Fatal(err)
	}
	unit := fileServiceUnit(c, "/usr/local/lib/calabi/files")
	for _, expected := range []string{"After=network.target calabi.service", "User=calabi-files", "RuntimeDirectory=calabi-files-7500", `"/srv/files 50%%"`, "NoNewPrivileges=true", "Restart=on-failure"} {
		if !strings.Contains(unit, expected) {
			t.Fatalf("missing %s in %s", expected, unit)
		}
	}
	c.User = "root\nExecStart=/evil"
	if validateFileServiceConfig(c) == nil {
		t.Fatal("unit injection accepted")
	}
	c.User = "calabi-files"
	c.Directory = "/srv/files\nExecStart=/evil"
	if validateFileServiceConfig(c) == nil {
		t.Fatal("directory injection accepted")
	}
	c.Directory = "/srv/files"
	for _, directory := range []string{c.StateDir, filepath.Join(c.StateDir, ".config", "Calabi", "file-agent")} {
		c.Directory = directory
		if validateFileServiceConfig(c) == nil {
			t.Fatal("private profile exposed as file directory")
		}
	}
	c.Directory = "/srv/files"
	c.Console = "http://198.51.100.7:7500"
	if validateFileServiceConfig(c) == nil {
		t.Fatal("remote daemon accepted")
	}
}
