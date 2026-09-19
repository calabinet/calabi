package main

// What a desktop keeps about the self-hosted server it is connected to: the config the console
// manages, which node this device is on the coordinator, and whether the
// coordinator's certificate stopped matching.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/calabi/calabi/apps/client/internal/creds"
	"github.com/calabi/calabi/apps/client/internal/trust"
)

// managedConfigPath is the tunnels.yaml the console writes when a person
// connects this machine to a self-hosted server, and the one the local daemon
// reads when it is given no --config. Whoever passes --config (or
// CALABI_DAEMON_CONFIG) keeps their own file, and the console does not move them
// between servers.
func managedConfigPath() string {
	dir, err := creds.DataDir()
	if err != nil {
		return "tunnels.yaml"
	}
	return filepath.Join(dir, "tunnels.yaml")
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
// from tunnels.yaml so a hand-written config is never rewritten for it, and so a
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
