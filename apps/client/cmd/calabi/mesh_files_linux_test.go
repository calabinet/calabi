//go:build linux

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/calabinet/calabi/apps/client/internal/filecontrol"
	"github.com/calabinet/calabi/apps/client/internal/filetransfer"
	"github.com/calabinet/calabi/apps/client/internal/status"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	"github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
)

func TestLinuxWildcardDaemonFileControl(t *testing.T) {
	t.Setenv("CALABI_STATUS_ADDR", "0.0.0.0:0")
	t.Setenv("CALABI_STATUS_SECRET", "test-only-console-secret-long-enough")
	isolateCreds(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	bound, done := startDaemonConsole(ctx, logger, status.New("test", ""), nil)
	defer func() { cancel(); <-done }()
	u, err := url.Parse(bound)
	if err != nil || u.Port() == "" || u.Port() == "0" {
		t.Fatalf("listener URL=%q error=%v", bound, err)
	}
	startFileControl(ctx, logger, nil, bound)
	console := "http://" + net.JoinHostPort("127.0.0.1", u.Port())
	_, err = filecontrol.Call(ctx, console, filecontrol.Request{Op: "snapshot"})
	// No mesh runner in this fixture: this RPC error proves we reached the
	// daemon's metadata controller via the real listener's chosen port.
	if err == nil || err.Error() != "mesh is not connected" {
		t.Fatalf("wildcard daemon IPC did not reach controller: %v", err)
	}
}

func TestLinuxOrdinaryUserFileAgent(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("file agent intentionally rejects root")
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	console := "http://127.0.0.1:17409"
	key := meshproto.NodeKey{1}
	c := &filecontrol.Control{Source: filecontrol.Source{View: func() (filecontrol.Snapshot, error) {
		return filecontrol.Snapshot{Ready: true, Scope: "test/org7", NodeKey: key.String(), Overlay: "127.0.0.1", RelayKbps: 4096}, nil
	}, Publish: func(context.Context, string, *meshpb.FileTransferInfo) error { return nil }}}
	done, err := filecontrol.Serve(ctx, c, console)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); <-done }()
	d, err := newDesktopFileAgent(ctx, console)
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	path := filepath.Join(t.TempDir(), "source with spaces.bin")
	data := bytes.Repeat([]byte("test"), 1024)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := d.stageLocal(path); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		d.stageMu.Lock()
		preparing := d.stageCancel != nil
		stageErr := d.stageError
		d.stageMu.Unlock()
		if !preparing {
			if stageErr != "" {
				t.Fatal(stageErr)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("staging stalled")
		}
		time.Sleep(10 * time.Millisecond)
	}
	w, err := d.ensure()
	if err != nil {
		t.Fatal(err)
	}
	if len(w.Staged()) != 1 || w.Staged()[0].Size != int64(len(data)) {
		t.Fatal("ordinary-user source staging failed")
	}
	if _, err := d.handle(fileAction{Action: "receiving", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if !w.Agent.Receiving() {
		t.Fatal("reception did not start")
	}
	d.poll()
	view, err := d.metadata()
	if err != nil || !view.OwnsLease {
		t.Fatalf("UID lease not owned: %v", err)
	}
	if _, err := d.handle(fileAction{Action: "receiving", Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if w.Agent.Receiving() {
		t.Fatal("reception retained")
	}
	existing := filepath.Join(t.TempDir(), "keep.bin")
	os.WriteFile(existing, []byte("keep"), 0600)
	if err := d.exportLocal("unknown", existing); err == nil {
		t.Fatal("export overwrote existing file")
	}
	if b, _ := os.ReadFile(existing); string(b) != "keep" {
		t.Fatal("existing output changed")
	}
	oldPin, oldHistory := d.identity.Fingerprint, d.identity.HistoryID()
	if _, err := d.handle(fileAction{Action: "identity_renew"}); err == nil {
		t.Fatal("maintenance did not require confirmation")
	}
	if _, err := d.handle(fileAction{Action: "identity_renew", Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	if d.identity.Fingerprint == oldPin || d.identity.HistoryID() != oldHistory {
		t.Fatal("CLI renewal identity/history mismatch")
	}
	reopened, err := d.ensure()
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Agent.Receiving() || len(reopened.Staged()) != 1 {
		t.Fatal("maintenance enabled reception or lost staged file")
	}
	d.close()
	if err := os.WriteFile(filepath.Join(d.dir, "file-identity.json"), []byte("damaged"), 0600); err != nil {
		t.Fatal(err)
	}
	recovery, err := newDesktopFileAgent(ctx, console)
	if err != nil {
		t.Fatal(err)
	}
	defer recovery.close()
	state, err := recovery.handle(fileAction{Action: "snapshot"})
	if err != nil {
		t.Fatal(err)
	}
	viewState := state.(map[string]any)
	if _, reservedError := viewState["error"]; reservedError || viewState["identity"] == nil || viewState["unavailable_reason"] == "" {
		t.Fatal("damaged identity recovery hidden by RPC error envelope")
	}
	if _, err := recovery.handle(fileAction{Action: "identity_reset", Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	recovered, err := recovery.ensure()
	if err != nil {
		t.Fatal(err)
	}
	if len(recovered.Staged()) != 1 || recovered.Agent.Receiving() {
		t.Fatal("damaged identity reset lost sources or enabled reception")
	}
}

func TestLinuxBrowserDirectoryAndRestart(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("ordinary user required")
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	console := "http://127.0.0.1:17419"
	control := &filecontrol.Control{Source: filecontrol.Source{View: func() (filecontrol.Snapshot, error) {
		return filecontrol.Snapshot{Ready: true, Scope: "test/browser", NodeKey: meshproto.NodeKey{9}.String(), Overlay: "127.0.0.1", RelayKbps: 4096}, nil
	}, Publish: func(context.Context, string, *meshpb.FileTransferInfo) error { return nil }}}
	done, err := filecontrol.Serve(ctx, control, console)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); <-done }()
	d, err := newDesktopFileAgent(ctx, console)
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err = os.WriteFile(filepath.Join(directory, "selected.bin"), []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "private.bin")
	os.WriteFile(outside, []byte("private"), 0600)
	if err = os.Symlink(outside, filepath.Join(directory, "escape.bin")); err != nil {
		t.Fatal(err)
	}
	b := &fileBrowser{d: d, root: root, directory: directory, authority: "127.0.0.1:7501", key: strings.Repeat("b", 64), action: d.handle}
	action := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://"+b.authority+"/file-web/action", strings.NewReader(body))
		r.Header.Set("Origin", "http://"+b.authority)
		r.AddCookie(&http.Cookie{Name: "calabi_file_browser", Value: b.key})
		w := httptest.NewRecorder()
		b.ServeHTTP(w, r)
		return w
	}
	if w := action(`{"action":"web_stage","names":["escape.bin"]}`); w.Code != 400 {
		t.Fatal("outside symlink accepted", w.Body.String())
	}
	if w := action(`{"action":"web_stage","names":["selected.bin"]}`); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	ws, err := d.ensure()
	if err != nil || len(ws.Staged()) != 1 {
		t.Fatal("staging failed", err)
	}
	if w := action(`{"action":"web_save","id":"unknown","name":"selected.bin"}`); w.Code != 400 {
		t.Fatal("overwritten existing file")
	}
	if w := action(`{"action":"web_save","id":"unknown","name":"failed.bin"}`); w.Code != 400 {
		t.Fatal("invalid export accepted")
	}
	if _, err = os.Stat(filepath.Join(directory, "failed.bin")); !os.IsNotExist(err) {
		t.Fatal("failed export retained")
	}
	firstKey, err := browserKey(d.dir)
	if err != nil {
		t.Fatal(err)
	}
	d.close()
	reopened, err := newDesktopFileAgent(ctx, console)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.close()
	secondKey, _ := browserKey(reopened.dir)
	if secondKey != firstKey {
		t.Fatal("access key lost on restart")
	}
	restored, err := reopened.ensure()
	if err != nil || len(restored.Staged()) != 1 || restored.Agent.Receiving() {
		t.Fatal("restart did not preserve sources with reception off", err)
	}
}

func TestLinuxCancellationRestartReclaimsOutboundLease(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("ordinary user required")
	}
	for _, scenario := range []struct{ hidden, remoteCancel bool }{{false, false}, {true, false}, {false, true}} {
		hidden := scenario.hidden
		t.Run(fmt.Sprint("hidden=", hidden, "/recipient=", scenario.remoteCancel), func(t *testing.T) {
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			console := "http://127.0.0.1:17429"
			remoteID, err := filetransfer.NewIdentity()
			if err != nil {
				t.Fatal(err)
			}
			ip := netip.MustParseAddr("127.0.0.1")
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			grant := filetransfer.Grant{Path: "direct", Peer: filetransfer.Peer{IP: ip, Fingerprint: remoteID.Fingerprint}, DeviceKey: "remote", Port: uint16(listener.Addr().(*net.TCPAddr).Port), Receiving: true}
			var offline, receivingPublished atomic.Bool
			control := &filecontrol.Control{Source: filecontrol.Source{View: func() (filecontrol.Snapshot, error) {
				g := grant
				g.Receiving = !offline.Load()
				return filecontrol.Snapshot{Ready: true, Scope: "test/cancel-lease", NodeKey: meshproto.NodeKey{11}.String(), Overlay: ip.String(), Peers: []filecontrol.Peer{{Grant: g, Incoming: true, ExpiresUnix: time.Now().Add(time.Minute).Unix()}}, Members: []filecontrol.Member{{IP: ip.String(), DeviceKey: "remote", Incoming: true}}}, nil
			}, Publish: func(_ context.Context, _ string, info *meshpb.FileTransferInfo) error {
				if info != nil && info.Receiving {
					receivingPublished.Store(true)
				}
				return nil
			}}}
			done, err := filecontrol.Serve(ctx, control, console)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { cancel(); <-done }()
			d, err := newDesktopFileAgent(ctx, console)
			if err != nil {
				t.Fatal(err)
			}
			defer d.close()
			r, err := filetransfer.NewReceiver(filetransfer.ReceiverConfig{Peer: filetransfer.Peer{IP: ip, Fingerprint: d.identity.Fingerprint}, Directory: t.TempDir(), Kbps: 8192, MaxBytes: 1 << 20, Allowed: func() bool { return true }, Durable: true, Scope: "remote"})
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			srv, served := r.Serve(listener, remoteID)
			defer func() { srv.Close(); <-served }()
			ws, err := d.ensure()
			if err != nil {
				t.Fatal(err)
			}
			source, err := ws.Stage(ctx, bytes.NewReader([]byte("test-only")), "cancel.bin", 9)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = d.handle(fileAction{Action: "send", Peer: ip.String(), IDs: []string{source.ID}}); err != nil {
				t.Fatal(err)
			}
			wait := func(why string, p func() bool) {
				t.Helper()
				deadline := time.Now().Add(15 * time.Second)
				for !p() {
					if time.Now().After(deadline) {
						t.Fatal(why)
					}
					time.Sleep(5 * time.Millisecond)
				}
			}
			wait("no offer", func() bool { return len(r.List()) == 1 })
			job := ws.Jobs()[0].ID
			offline.Store(true)
			d.poll()
			if scenario.remoteCancel {
				err = ws.Pause(job)
			} else {
				err = ws.Cancel(job)
			}
			if err != nil {
				t.Fatal(err)
			}
			if hidden {
				if err = ws.ForgetJob(job); err != nil {
					t.Fatal(err)
				}
			}
			d.close()
			reopened, err := newDesktopFileAgent(ctx, console)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.close()
			restored, err := reopened.ensure()
			if err != nil {
				t.Fatal(err)
			}
			if !restored.NeedsControlSession() || restored.Agent.Receiving() {
				t.Fatal("pending intent lost or reception enabled")
			}
			if hidden && len(restored.Jobs()) != 0 {
				t.Fatal("hidden task resurrected")
			}
			view, err := reopened.metadata()
			if err != nil || view.OwnsLease {
				t.Fatal("test did not start without ownership", err)
			}
			offline.Store(false)
			if scenario.remoteCancel {
				if err = r.Cancel(r.List()[0].ID); err != nil {
					t.Fatal(err)
				}
			}
			reopened.poll()
			view, err = reopened.metadata()
			if err != nil || !view.OwnsLease {
				t.Fatal("pending cancellation did not reclaim outbound lease", err)
			}
			if receivingPublished.Load() || restored.Agent.Receiving() {
				t.Fatal("control retry enabled incoming reception")
			}
			wait("offline cancellation never synchronized", func() bool { return !restored.NeedsControlSession() && r.List()[0].State == "cancelled" })
			if hidden && len(restored.Jobs()) != 0 {
				t.Fatal("removed task reappeared")
			}
		})
	}
}
