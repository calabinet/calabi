//go:build linux

package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/calabinet/calabi/apps/client/internal/filecontrol"
	"github.com/calabinet/calabi/apps/client/internal/filetransfer"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	"github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
)

func TestBrowserAuthorizationDoesNotInterruptApprovedTransfer(t *testing.T) {
	for _, scenario := range []string{"logout", "expiry", "revoke-all"} {
		t.Run(scenario, func(t *testing.T) {
			if os.Geteuid() == 0 {
				t.Skip("ordinary user fixture")
			}
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			from, _ := filetransfer.NewIdentity()
			local := meshproto.NodeKey{1}
			remote := meshproto.NodeKey{2}
			console := "http://127.0.0.1:17459"
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
			sender, err := filetransfer.NewWorkspace(filetransfer.AgentConfig{Identity: from, Directory: t.TempDir(), Scope: "sender", LocalIP: netip.MustParseAddr("127.0.0.2"), Port: 17401, Kbps: 2048, MaxBytes: 8 << 20, Resolve: func(netip.Addr) (filetransfer.Grant, bool) {
				return filetransfer.Grant{Peer: filetransfer.Peer{IP: netip.MustParseAddr("127.0.0.1"), Fingerprint: d.identity.Fingerprint}, DeviceKey: local.String(), Port: 17401, Receiving: true}, true
			}, Incoming: func(netip.Addr, uint16) bool { return false }})
			if err != nil {
				t.Fatal(err)
			}
			defer sender.Close()
			data := bytes.Repeat([]byte("verified bytes"), 40000)
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
			auth := newBrowserAuth()
			now := time.Unix(10000, 0)
			auth.now = func() time.Time { return now }
			browser := &fileBrowser{authority: "127.0.0.1:7501", auth: auth, d: d, action: d.handle}
			request := func(path, body, token string) *httptest.ResponseRecorder {
				req := httptest.NewRequest("POST", "http://"+browser.authority+path, strings.NewReader(body))
				req.Header.Set("Origin", "http://"+browser.authority)
				if token != "" {
					req.AddCookie(&http.Cookie{Name: "calabi_file_browser", Value: token})
				}
				w := httptest.NewRecorder()
				browser.ServeHTTP(w, req)
				return w
			}
			pair, _ := auth.issuePair()
			login := request("/file-web/session", `{"pair":"`+pair+`"}`, "")
			if login.Code != 200 {
				t.Fatal(login.Body.String())
			}
			cookie := login.Result().Cookies()[0].Value
			approved := request("/file-web/action", `{"action":"decide","ids":["`+id+`"],"accept":true}`, cookie)
			if approved.Code != 200 {
				t.Fatal(approved.Body.String())
			}
			wait(func() bool { r := d.w.Agent.List()[0].Transfer; return r.Offset > 0 && r.Offset < r.Size })
			switch scenario {
			case "logout":
				if w := request("/file-web/logout", `{}`, cookie); w.Code != 200 {
					t.Fatal("logout failed")
				}
			case "expiry":
				now = now.Add(browserSessionTTL)
			case "revoke-all":
				dir, e := os.MkdirTemp("", "cba-transfer-")
				if e != nil {
					t.Fatal(e)
				}
				defer os.RemoveAll(dir)
				socket := filepath.Join(dir, "auth.sock")
				close, e := startBrowserAuth(ctx, socket, "http://"+browser.authority+"/", auth)
				if e != nil {
					t.Fatal(e)
				}
				defer close()
				if _, e = browserAuthRequest(socket, "revoke-all"); e != nil {
					t.Fatal(e)
				}
			}
			if w := request("/file-web/action", `{"action":"snapshot"}`, cookie); w.Code != 401 {
				t.Fatal("revoked browser still authorized", w.Code)
			}
			if d.ctx.Err() != nil || !d.w.Agent.Receiving() {
				t.Fatal("browser auth changed file-agent lifetime or reception")
			}
			wait(func() bool { return d.w.Agent.List()[0].Transfer.State == "completed" })
			var received bytes.Buffer
			if e := d.w.Agent.CopyCompleted(ctx, id, &received); e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(received.Bytes(), data) {
				t.Fatal("approved transfer corrupted after browser revocation")
			}

		})
	}
}
