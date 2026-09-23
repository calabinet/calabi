package main

// What a desktop keeps about the self-hosted server it is connected to: the config the console
// manages, which node this device is on the coordinator, and whether the
// coordinator's certificate stopped matching.

import (
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/calabinet/calabi/apps/client/internal/creds"
	"github.com/calabinet/calabi/apps/client/internal/trust"
)

// managedConfigPath is the calabi.yaml the console writes when a person
// connects this machine to a self-hosted server, and the one the local daemon
// reads when it is given no --config. Whoever passes --config (or
// CALABI_DAEMON_CONFIG) keeps their own file, and the console does not move them
// between servers.
//
// It resolves to the legacy name while that is the only file present, so a
// machine whose rename could not be performed keeps running off the file it
// has instead of silently starting from empty.
func managedConfigPath() string {
	dir, err := creds.DataDir()
	if err != nil {
		return managedConfigName
	}
	p := filepath.Join(dir, managedConfigName)
	if _, err := os.Stat(p); err != nil {
		if legacy := filepath.Join(dir, legacyManagedConfigName); fileExists(legacy) {
			return legacy
		}
	}
	return p
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// The file was called tunnels.yaml until 1.15.0, when it stopped being about
// tunnels: `tunnels: []` with a `server:` block is a complete, ordinary config
// for a machine that only joins.
const (
	managedConfigName       = "calabi.yaml"
	legacyManagedConfigName = "tunnels.yaml"
)

// adoptLegacyManagedConfig renames a tunnels.yaml left by an earlier version.
// Called before anything reads the managed config.
//
// A rename rather than leaving both: two files with the same job, one of them
// stale, is the state that produces "I edited the config and nothing happened".
// Best-effort — if it fails, managedConfigPath keeps resolving to the old file
// and the machine goes on working under the old name.
//
// The interesting case is two PROCESSES arriving together — the daemon starting
// while `calabi http` runs is the ordinary way this machine looks — so the loser
// of the rename is not an error to report: it is told apart from a real failure
// by asking whether the new file is there now, which is all the caller wanted.
// A sync.Once would have looked like it covered this and covered nothing.
func adoptLegacyManagedConfig(logger *slog.Logger) {
	dir, err := creds.DataDir()
	if err != nil {
		return
	}
	newPath := filepath.Join(dir, managedConfigName)
	oldPath := filepath.Join(dir, legacyManagedConfigName)
	if fileExists(newPath) || !fileExists(oldPath) {
		return // already migrated, written fresh, or nothing to adopt
	}
	switch err := os.Rename(oldPath, newPath); {
	case err == nil:
		if logger != nil {
			logger.Info("config renamed", "from", oldPath, "to", newPath)
		}
	case fileExists(newPath):
		// Someone else got there first.
	case logger != nil:
		logger.Warn("could not rename the config to its new name; still reading the old one",
			"from", oldPath, "to", newPath, "err", err)
	}
}

// loadLocalConfigOrEmpty is loadLocalConfig for the managed file, which may not
// exist yet: a machine switched to the local daemon before it was connected to
// anything starts with nothing configured, and the console shows it how to
// connect. The managed file may still name the edge, as the console used to
// write it: those settings are set aside and returned, for the caller to say so
// and rewrite the file.
func loadLocalConfigOrEmpty(path string, managed bool) (*localConfig, []string, error) {
	if !managed {
		cfg, err := loadLocalConfig(path)
		return cfg, nil, err
	}
	cfg, removed, err := readLocalConfig(path)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return &localConfig{}, nil, nil
	}
	return cfg, removed, err
}

// writeLocalConfig writes cfg the way the supervisor persists it.
func writeLocalConfig(path string, cfg localConfig) error {
	if cfg.Tunnels == nil {
		cfg.Tunnels = []localTunnelConfig{}
	}
	data, err := marshalLocalConfig(cfg)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// firstPin is what a certificate-changed prompt shows as "was": the pinned
// fingerprint, or nothing when the trust was a CA or the system's roots.
func firstPin(t trust.Config) string {
	if t.Mode == trust.Pin && len(t.Pins) > 0 {
		return t.Pins[0]
	}
	return ""
}

// --- which node this device is -----------------------------------------------

// meshReauthRecord is which node this device is on a self-hosted coordinator
// and whether the coordinator takes it back by proof alone. It is kept apart
// from calabi.yaml so a hand-written config is never rewritten for it, and so a
// device that joined by a one-time invite can come back after a restart without
// the key the invite spent.
type meshReauthRecord struct {
	Coord  string `json:"coord"`
	NodeID int64  `json:"node_id"`
	Reauth bool   `json:"reauth"`
}

var meshReauthMu sync.Mutex

func meshReauthPath() string {
	dir, err := creds.DataDir()
	if err != nil {
		return "mesh-reauth.json"
	}
	return filepath.Join(dir, "mesh-reauth.json")
}

// loadMeshReauth returns the record for coord, or the zero record when the one
// on disk is for another coordinator (or there is none).
func loadMeshReauth(coord string) meshReauthRecord {
	meshReauthMu.Lock()
	defer meshReauthMu.Unlock()
	b, err := os.ReadFile(meshReauthPath())
	if err != nil {
		return meshReauthRecord{}
	}
	var r meshReauthRecord
	if json.Unmarshal(b, &r) != nil || r.Coord != coord {
		return meshReauthRecord{}
	}
	return r
}

func saveMeshReauth(r meshReauthRecord) error {
	meshReauthMu.Lock()
	defer meshReauthMu.Unlock()
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	p := meshReauthPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func forgetMeshReauth() {
	meshReauthMu.Lock()
	defer meshReauthMu.Unlock()
	_ = os.Remove(meshReauthPath())
}

// canRejoin: with this record, the node can join without an auth key.
func (r meshReauthRecord) canRejoin() bool { return r.NodeID != 0 && r.Reauth }

// --- a certificate that stopped matching -------------------------------------

// certWatch remembers that a server presented a certificate its saved trust
// refuses. Only a person can accept a new certificate — they compare it with
// what the server prints — so until then the console shows both fingerprints.
// The connection keeps retrying with the old trust meanwhile: an administrator
// who puts the old certificate back gets every device back untouched.
type certWatch struct {
	mu        sync.Mutex
	presented string
	pinned    string
}

func (w *certWatch) set(presented, pinned string) {
	w.mu.Lock()
	w.presented, w.pinned = presented, pinned
	w.mu.Unlock()
}

func (w *certWatch) clear() { w.set("", "") }

func (w *certWatch) get() (presented, pinned string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.presented, w.pinned
}
