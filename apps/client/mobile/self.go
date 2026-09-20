package mobile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"

	"github.com/calabinet/calabi/apps/client/internal/creds"
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

// selfKey names the network an engine is on in self.json: the organization's
// id, or the self-hosted server.
func (e *engine) selfKey(orgID int64) string {
	if e.profile != nil {
		return serverKey(e.profile.Server)
	}
	return orgKey(orgID)
}

func orgKey(orgID int64) string {
	if orgID == 0 { // an enrollment that predates org_id: the session's org
		if cfg, _ := creds.Load(); cfg != nil {
			orgID = cfg.ActiveOrgID
		}
	}
	return strconv.FormatInt(orgID, 10)
}

// serverKey is a self-hosted server's entry in self.json.
func serverKey(server string) string { return "server:" + server }

// rememberSelf records overlay as this phone's address in the network k names
// (engine.selfKey).
func (c *Core) rememberSelf(k, overlay string) {
	if overlay == "" {
		return
	}
	c.selfMu.Lock()
	defer c.selfMu.Unlock()
	all := c.readSelf()
	if all[k] == overlay {
		return
	}
	all[k] = overlay
	b, _ := json.Marshal(all)
	if err := os.WriteFile(c.selfPath(), b, 0o600); err != nil {
		c.logger.Warn("could not remember this phone's mesh address", "err", err)
	}
}

// selfOverlay is this phone's last known address in the network it is on — the
// self-hosted server, or the active organization's meshnet — or "".
func (c *Core) selfOverlay() string {
	key := ""
	if p := c.selfHosted(); p != nil {
		key = serverKey(p.Server)
	} else {
		cfg, _ := creds.Load()
		if cfg == nil {
			return ""
		}
		key = strconv.FormatInt(cfg.ActiveOrgID, 10)
	}
	c.selfMu.Lock()
	defer c.selfMu.Unlock()
	return c.readSelf()[key]
}
