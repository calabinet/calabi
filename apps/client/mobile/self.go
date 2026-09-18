package mobile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"

	"github.com/calabi/calabi/apps/client/internal/creds"
)

// This phone's own mesh address in each organization it has joined, kept so the
// app can leave the phone out of the org's device list while it is disconnected.
// The list still carries the phone then — the coordinator keeps a node and its
// address across disconnects — and with no live session there is nothing else
// that says which entry is this phone. Per organization, because each meshnet
// assigns its own address.

func (c *Core) selfPath() string { return filepath.Join(c.cfg.StateDir, "self.json") }

func (c *Core) readSelf() map[string]string {
	out := map[string]string{}
	if b, err := os.ReadFile(c.selfPath()); err == nil {
		_ = json.Unmarshal(b, &out)
	}
	return out
}

// rememberSelf records overlay as this phone's address in orgID's meshnet.
func (c *Core) rememberSelf(orgID int64, overlay string) {
	if overlay == "" {
		return
	}
	if orgID == 0 { // an enrollment that predates org_id: the session's org
		if cfg, _ := creds.Load(); cfg != nil {
			orgID = cfg.ActiveOrgID
		}
	}
	c.selfMu.Lock()
	defer c.selfMu.Unlock()
	all := c.readSelf()
	key := strconv.FormatInt(orgID, 10)
	if all[key] == overlay {
		return
	}
	all[key] = overlay
	b, _ := json.Marshal(all)
	if err := os.WriteFile(c.selfPath(), b, 0o600); err != nil {
		c.logger.Warn("could not remember this phone's mesh address", "err", err)
	}
}

// selfOverlay is this phone's last known address in the active organization's
// meshnet, or "".
func (c *Core) selfOverlay() string {
	cfg, _ := creds.Load()
	if cfg == nil {
		return ""
	}
	c.selfMu.Lock()
	defer c.selfMu.Unlock()
	return c.readSelf()[strconv.FormatInt(cfg.ActiveOrgID, 10)]
}
