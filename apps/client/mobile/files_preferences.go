package mobile

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/calabinet/calabi/apps/client/internal/filetransfer"
)

// One choice, bound to the authenticated workspace. Returning to an old
// organization must not resurrect its previous permission to receive.
type fileReceptionPreference struct {
	Context string `json:"context"`
	Scope   string `json:"scope"`
	Enabled bool   `json:"enabled"`
}

// Caller holds fileMu, including when changing authentication context.
func (c *Core) readFileReception() (fileReceptionPreference, error) {
	if c.fileReceptionPending != nil {
		return *c.fileReceptionPending, nil
	}
	var p fileReceptionPreference
	b, err := os.ReadFile(filepath.Join(c.cfg.StateDir, "files-v1", "receive-settings.json"))
	if errors.Is(err, os.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return p, err
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return fileReceptionPreference{}, err
	}
	return p, nil
}

func (c *Core) saveFileReception(p fileReceptionPreference) (retErr error) {
	defer func() {
		if retErr != nil {
			c.fileReceptionPending = &p
		} else {
			c.fileReceptionPending = nil
		}
	}()
	dir := filepath.Join(c.cfg.StateDir, "files-v1")
	if err := filetransfer.PrivateDirectory(dir); err != nil {
		return err
	}
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "receive-settings-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(dir, "receive-settings.json"))
}

func (c *Core) fileReceptionRequested(f *mobileFiles) bool {
	p, err := c.readFileReception()
	return err == nil && f != nil && p.Enabled && p.Context == f.contextKey && p.Scope == f.scope
}

func (c *Core) restoreFileReception(f *mobileFiles) error {
	if c.fileReceptionPending != nil {
		if err := c.saveFileReception(*c.fileReceptionPending); err != nil {
			_ = f.w.Agent.SetReceiving(false)
			return err
		}
	}
	p, err := c.readFileReception()
	if err != nil {
		_ = f.w.Agent.SetReceiving(false)
		return err
	}
	if p.Context != f.contextKey || p.Scope != f.scope {
		p = fileReceptionPreference{Context: f.contextKey, Scope: f.scope}
		if err := c.saveFileReception(p); err != nil {
			_ = f.w.Agent.SetReceiving(false)
			return err
		}
	}
	if f.w.Agent.Receiving() == p.Enabled {
		return nil
	}
	return f.w.Agent.SetReceiving(p.Enabled)
}

func (c *Core) clearFileReception() error {
	c.fileMu.Lock()
	defer c.fileMu.Unlock()
	c.closeFilesLocked(true)
	return c.saveFileReception(fileReceptionPreference{})
}
