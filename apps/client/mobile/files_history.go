package mobile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/calabinet/calabi/apps/client/internal/creds"
	"github.com/calabinet/calabi/apps/client/internal/filetransfer"
)

// The marker selects one private workspace, never a caller supplied path.
// Signing out or switching organizations makes the old context inaccessible.
type fileHistory struct {
	Context, Scope, Overlay, Fingerprint string
}

func fileHash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func (c *Core) fileContext() string {
	if p := c.selfHosted(); p != nil {
		return serverKey(p.Server)
	}
	cfg, _ := creds.Load()
	if cfg == nil || cfg.AccessToken == "" || cfg.User.ID == 0 || cfg.ActiveOrgID == 0 {
		return ""
	}
	return fmt.Sprintf("%s/user:%d/org:%d", c.cfg.BFFURL, cfg.User.ID, cfg.ActiveOrgID)
}

func (c *Core) rememberFiles(f *mobileFiles, overlay string) error {
	if f.contextKey == "" {
		return errors.New("file history has no signed-in context")
	}
	b, err := json.Marshal(fileHistory{f.contextKey, f.scope, overlay, f.id.HistoryID()})
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(c.cfg.StateDir, "files-v1", "context-"+fileHash(f.contextKey)+".json"), b)
}

// Opens local journals only: no listener, peer authorization or publication.
// Missing history must not create an identity or any file-transfer state.
func (c *Core) filesHistory() (*mobileFiles, error) {
	key := c.fileContext()
	if key == "" {
		return nil, errors.New("connect to the mesh first")
	}
	if f := c.files; f != nil && f.contextKey == key && f.w.Agent.Alive() && !f.failed.Load() {
		return f, nil
	}
	if c.files != nil {
		c.closeFilesLocked(false)
	}
	base := filepath.Join(c.cfg.StateDir, "files-v1")
	b, err := os.ReadFile(filepath.Join(base, "context-"+fileHash(key)+".json"))
	if err != nil {
		return nil, errors.New("connect to the mesh first")
	}
	var record fileHistory
	if len(b) > 16384 || json.Unmarshal(b, &record) != nil || record.Context != key || record.Scope == "" {
		return nil, errors.New("invalid private file history")
	}
	local, err := netip.ParseAddr(record.Overlay)
	if err != nil {
		return nil, errors.New("invalid private file history address")
	}
	if _, err = os.Stat(filepath.Join(base, "file-identity.json")); err != nil {
		return nil, err
	}
	id, err := filetransfer.LoadIdentity(base)
	if err != nil {
		return nil, err
	}
	if id.HistoryID() != record.Fingerprint {
		return nil, errors.New("file history belongs to another identity")
	}
	w, err := filetransfer.NewWorkspace(filetransfer.AgentConfig{Identity: id, Directory: filepath.Join(base, fileHash(record.Scope)), Scope: record.Scope, LocalIP: local, Port: 17401, Kbps: filetransfer.DefaultKbps, MaxBytes: 8 << 30, Resolve: func(netip.Addr) (filetransfer.Grant, bool) { return filetransfer.Grant{}, false }, Incoming: func(netip.Addr, uint16) bool { return false }})
	if err != nil {
		return nil, err
	}
	done := make(chan struct{})
	close(done)
	paths := &atomic.Value{}
	paths.Store(map[string]string{})
	f := &mobileFiles{w: w, id: id, scope: record.Scope, contextKey: key, paths: paths, cancel: func() {}, done: done}
	c.files = f
	return f, nil
}

func (c *Core) filesLive(f *mobileFiles) bool {
	if f == nil || f.e == nil || f.ctrl == nil || f.failed.Load() || c.currentEngine() != f.e || !f.ctrl.FileTransferReady() {
		return false
	}
	f.e.mu.Lock()
	defer f.e.mu.Unlock()
	return f.e.ctrl == f.ctrl && f.e.state == stateConnected && c.fileContext() == f.contextKey
}
