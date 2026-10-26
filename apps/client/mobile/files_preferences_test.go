package mobile

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/calabinet/calabi/apps/client/internal/creds"
	"github.com/calabinet/calabi/apps/client/internal/filetransfer"
)

func TestReceptionSaveFailureDoesNotPreventLogout(t *testing.T) {
	c := newTestCore(t, &fakeBFF{}, &fakePlatform{})
	signIn(t, c)
	path := filepath.Join(c.cfg.StateDir, "files-v1", "receive-settings.json")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "blocker"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if r := c.Call("POST", "/v1/auth/logout", nil); r.Status != 200 {
		t.Fatalf("logout blocked by file settings: %s", r.Body)
	}
	cfg, err := creds.Load()
	if err != nil || cfg.AccessToken != "" {
		t.Fatalf("session retained: %v", err)
	}
	if r := c.Call("POST", "/v1/auth/login", []byte(`{"email":"ada@example.com","password":"hunter2"}`)); r.Status != 500 {
		t.Fatalf("sign-in bypassed unpersisted clear: %d %s", r.Status, r.Body)
	}
	if err := os.Remove(filepath.Join(path, "blocker")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	signIn(t, c)
	p, err := c.readFileReception()
	if err != nil || p.Enabled {
		t.Fatalf("sign-in restored stale reception: %v", err)
	}
}

func TestReceptionPreferenceRestartOfflineOffAndAuthBoundaries(t *testing.T) {
	c := newTestCore(t, &fakeBFF{}, &fakePlatform{})
	signIn(t, c)
	c.cfg.FileTransferV1 = true
	c.api = c.routes()
	id, err := filetransfer.LoadIdentity(filepath.Join(c.cfg.StateDir, "files-v1"))
	if err != nil {
		t.Fatal(err)
	}
	f := &mobileFiles{contextKey: c.fileContext(), scope: "current-device", id: id}
	if err := os.MkdirAll(filepath.Join(c.cfg.StateDir, "files-v1", fileHash(f.scope)), 0700); err != nil {
		t.Fatal(err)
	}
	if err := c.rememberFiles(f, "100.64.0.1"); err != nil {
		t.Fatal(err)
	}
	if c.fileReceptionRequested(f) {
		t.Fatal("enabled by default")
	}
	if err := c.saveFileReception(fileReceptionPreference{Context: f.contextKey, Scope: f.scope, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	c.Disconnect() // Ordinary transport shutdown preserves the user's choice.
	if !c.fileReceptionRequested(f) {
		t.Fatal("disconnect erased preference")
	}
	// Recreate the reader, as after a process restart, using the same private state.
	restarted := &Core{cfg: c.cfg}
	if !restarted.fileReceptionRequested(f) {
		t.Fatal("restart lost preference")
	}
	r := c.Call("GET", "/v1/files", nil)
	var out struct {
		Available, Receiving bool
		Requested            bool `json:"receiving_requested"`
	}
	if err := json.Unmarshal(r.Body, &out); err != nil {
		t.Fatal(err)
	}
	if out.Available || out.Receiving || !out.Requested {
		t.Fatalf("offline snapshot: %s", r.Body)
	}
	if r := c.Call("POST", "/v1/files/action", []byte(`{"action":"receiving","enabled":false}`)); r.Status != 200 {
		t.Fatalf("offline off: %s", r.Body)
	}
	if restarted.fileReceptionRequested(f) {
		t.Fatal("off not persisted")
	}
	if err := c.saveFileReception(fileReceptionPreference{Context: f.contextKey, Scope: f.scope, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if r := c.Call("POST", "/v1/orgs/switch", []byte(`{"target_org_id":8}`)); r.Status != 200 {
		t.Fatalf("org switch: %s", r.Body)
	}
	if restarted.fileReceptionRequested(f) {
		t.Fatal("org switch retained preference")
	}
	if err := c.saveFileReception(fileReceptionPreference{Context: f.contextKey, Scope: f.scope, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if r := c.Call("POST", "/v1/auth/logout", nil); r.Status != 200 {
		t.Fatalf("logout: %s", r.Body)
	}
	signIn(t, c)
	if restarted.fileReceptionRequested(f) {
		t.Fatal("relogin resurrected preference")
	}
	c.stopFiles(false)
}

func TestReceptionScopeMismatchAndCorruptPreferenceFailClosed(t *testing.T) {
	c := newTestCore(t, &fakeBFF{}, &fakePlatform{})
	signIn(t, c)
	id, err := filetransfer.LoadIdentity(filepath.Join(c.cfg.StateDir, "files-v1"))
	if err != nil {
		t.Fatal(err)
	}
	w, err := filetransfer.NewWorkspace(filetransfer.AgentConfig{Identity: id, Directory: t.TempDir(), Scope: "new-scope", LocalIP: netip.MustParseAddr("127.0.0.1"), Port: 17401, Kbps: 512, MaxBytes: 8 << 20, Incoming: func(netip.Addr, uint16) bool { return false }, Resolve: func(netip.Addr) (filetransfer.Grant, bool) { return filetransfer.Grant{}, false }})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	f := &mobileFiles{contextKey: c.fileContext(), scope: "new-scope", w: w}
	if err := c.saveFileReception(fileReceptionPreference{Context: f.contextKey, Scope: "old-scope", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := c.restoreFileReception(f); err != nil {
		t.Fatal(err)
	}
	if w.Agent.Receiving() {
		t.Fatal("old scope restored")
	}
	f.scope = "old-scope"
	if c.fileReceptionRequested(f) {
		t.Fatal("old scope revived after switching back")
	}
	if err := os.WriteFile(filepath.Join(c.cfg.StateDir, "files-v1", "receive-settings.json"), []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.restoreFileReception(f); err == nil || w.Agent.Receiving() {
		t.Fatal("corrupt preference did not fail closed")
	}
	// A failed OFF write must never let the periodic restore read the old ON
	// value and silently reopen reception. Removing the obstruction permits retry.
	f.scope = "new-scope"
	path := filepath.Join(c.cfg.StateDir, "files-v1", "receive-settings.json")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "blocker"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.saveFileReception(fileReceptionPreference{}); err == nil {
		t.Fatal("expected save failure")
	}
	if err := c.restoreFileReception(f); err == nil || w.Agent.Receiving() {
		t.Fatal("failed save reopened reception")
	}
	if err := os.Remove(filepath.Join(path, "blocker")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := c.restoreFileReception(f); err != nil {
		t.Fatal(err)
	}
	if c.fileReceptionRequested(f) || c.fileReceptionPending != nil {
		t.Fatal("OFF retry not committed")
	}
}
