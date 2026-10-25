package mobile

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/calabinet/calabi/apps/client/internal/creds"
	"github.com/calabinet/calabi/apps/client/internal/filetransfer"
)

func TestFileTransferV1RequiresOptInAndCurrentMesh(t *testing.T) {
	c := newTestCore(t, &fakeBFF{}, &fakePlatform{})
	if r := c.Call("GET", "/v1/files", nil); r.Status != 404 {
		t.Fatalf("default v1 route: %d", r.Status)
	}
	c.cfg.FileTransferV1 = true
	c.api = c.routes()
	r := c.Call("GET", "/v1/files", nil)
	if r.Status != 200 {
		t.Fatalf("status: %d", r.Status)
	}
	var out map[string]any
	if err := json.Unmarshal(r.Body, &out); err != nil {
		t.Fatal(err)
	}
	if out["available"] != false {
		t.Fatal("disconnected phone advertised receiving")
	}
	if r := c.Call("POST", "/v1/files/action", []byte(`{"action":"receiving","enabled":true}`)); r.Status != 409 {
		t.Fatalf("enabled without mesh: %d", r.Status)
	}
	if c.files != nil {
		t.Fatal("disconnected phone opened an agent")
	}
	if _, err := os.Stat(filepath.Join(c.cfg.StateDir, "files-v1")); !os.IsNotExist(err) {
		t.Fatal("disconnected phone generated file state")
	}
}

func TestFileHistoryOfflineIsPrivateToSignedInNetwork(t *testing.T) {
	c := newTestCore(t, &fakeBFF{}, &fakePlatform{})
	signIn(t, c)
	c.cfg.FileTransferV1 = true
	c.api = c.routes()
	base := filepath.Join(c.cfg.StateDir, "files-v1")
	if err := os.MkdirAll(base, 0700); err != nil {
		t.Fatal(err)
	}
	id, err := filetransfer.LoadIdentity(base)
	if err != nil {
		t.Fatal(err)
	}
	scope := "test-coord/org7/node1/" + id.Fingerprint
	dir := filepath.Join(base, fileHash(scope))
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	w, err := filetransfer.NewWorkspace(filetransfer.AgentConfig{Identity: id, Directory: dir, Scope: scope, LocalIP: netip.MustParseAddr("100.64.0.1"), Port: 17401, Kbps: 512, MaxBytes: 8 << 30, Resolve: func(netip.Addr) (filetransfer.Grant, bool) { return filetransfer.Grant{}, false }, Incoming: func(netip.Addr, uint16) bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Stage(context.Background(), bytes.NewReader([]byte("private")), "private.txt", 7); err != nil {
		t.Fatal(err)
	}
	f := &mobileFiles{scope: scope, contextKey: c.fileContext(), id: id}
	if err := c.rememberFiles(f, "100.64.0.1"); err != nil {
		t.Fatal(err)
	}
	w.Close()
	defer c.stopFiles(false)
	r := c.Call("GET", "/v1/files", nil)
	var out struct {
		Available bool                      `json:"available"`
		Sources   []filetransfer.StagedFile `json:"sources"`
	}
	if err := json.Unmarshal(r.Body, &out); err != nil {
		t.Fatal(err)
	}
	if out.Available || len(out.Sources) != 1 || out.Sources[0].Name != "private.txt" || c.files.ctrl != nil {
		t.Fatalf("offline history: %s", r.Body)
	}
	if r := c.Call("POST", "/v1/files/action", []byte(`{"action":"receiving","enabled":true}`)); r.Status != 409 {
		t.Fatal("offline history enabled receiving")
	}
	if r := c.Call("POST", "/v1/files/action", []byte(`{"action":"identity_renew"}`)); r.Status != 409 {
		t.Fatal("renewal skipped local confirmation")
	}
	if r := c.Call("POST", "/v1/files/action", []byte(`{"action":"identity_renew","confirmed":true}`)); r.Status != 200 {
		t.Fatalf("offline renewal: %s", r.Body)
	}
	r = c.Call("GET", "/v1/files", nil)
	if err := json.Unmarshal(r.Body, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Sources) != 1 || c.files.id.Fingerprint == id.Fingerprint || c.files.id.HistoryID() != id.HistoryID() {
		t.Fatal("mobile renewal lost history or kept old pin")
	}
	if r := c.Call("POST", "/v1/files/action", []byte(`{"action":"identity_reset","confirmed":true}`)); r.Status != 200 {
		t.Fatalf("offline reset: %s", r.Body)
	}
	r = c.Call("GET", "/v1/files", nil)
	if err := json.Unmarshal(r.Body, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Sources) != 1 || c.files.w.Agent.Receiving() {
		t.Fatal("mobile reset lost source or enabled reception")
	}
	cfg, _ := creds.Load()
	cfg.ActiveOrgID++
	if err := creds.Save(cfg); err != nil {
		t.Fatal(err)
	}
	r = c.Call("GET", "/v1/files", nil)
	if err := json.Unmarshal(r.Body, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Sources) != 0 || c.files != nil {
		t.Fatalf("another org saw private history: %s", r.Body)
	}
}
