// Package creds reads + writes the calabi CLI's local credentials file.
//
//	$XDG_CONFIG_HOME/calabi/config.json   on Linux/macOS
//	%LOCALAPPDATA%\calabi\config.json     on Windows
//
// Schema is intentionally JSON (not protobuf) so a user can hand-edit
// when needed without pulling protoc.
package creds

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Config is the on-disk credential store.
type Config struct {
	// Server is the default calabi-edge control endpoint.
	Server string `json:"server,omitempty"`
	// AccessToken is the most recent login session token. Format
	// matches identity-svc's ValidateToken accepted shapes after the
	// cutover: JWT (issued by Login) or "tk_..." (API key).
	// Old creds files written by CLI may still carry "usr_..." here;
	// the server now rejects those with an "invalid token" response,
	// which makes the CLI re-prompt for credentials.
	AccessToken string `json:"access_token,omitempty"`
	// RefreshToken is the long-lived refresh credential.
	RefreshToken string `json:"refresh_token,omitempty"`
	// User identifies the currently-logged-in user (display only).
	User struct {
		ID    int64  `json:"id"`
		Email string `json:"email"`
	} `json:"user,omitempty"`
	// APIKey is the per-machine API key (preferred over AccessToken
	// for non-interactive tools / scripts).
	APIKey string `json:"api_key,omitempty"`
	// Fingerprint is a stable 32-hex per-install device id.
	// Generated lazily by Fingerprint() on first call and persisted, so
	// `calabi clients list` shows one row per machine rather than per
	// session.
	Fingerprint string `json:"fingerprint,omitempty"`
	// DeviceID is the int64 clients.id returned by identity-svc on the
	// most recent RegisterClient. Sent in the AUTH frame so the edge can
	// track live presence per device. Refreshed on every EnsureClientRegistered.
	DeviceID int64 `json:"device_id,omitempty"`
	// ActiveOrgID mirrors the org_id claim of the saved AccessToken.
	// surfaced separately so `calabi org current` can display the
	// active Org without parsing the JWT, and so a stale token (refresh
	// expired) still shows the user where they were. Updated on login
	// and on `calabi org switch`. 0 = unknown / never switched.
	ActiveOrgID int64 `json:"active_org_id,omitempty"`
	// EdgeRegion is the daemon's preferred edge region. When set,
	// the daemon calls identity-svc.ListEdges(region) at boot and dials
	// the first healthy edge in that region instead of the CALABI_SERVER
	// default. Empty = no preference; daemon uses CALABI_SERVER /
	// defaultServer as before.
	//
	// Sticky once set — `calabi org switch` does NOT touch this. Use
	// `calabi --edge-region <region>` (or set CALABI_EDGE_REGION in env)
	// to override per-run.
	EdgeRegion string `json:"edge_region,omitempty"`
	// LastEdgeNodeID is the edge_node_id the daemon successfully dialed
	// on its previous run. Persisted so the next boot can reuse the same
	// edge instead of getting load-balanced to a different one — a
	// no-op-looking change that's actually load-bearing because tunnel
	// domains are bound to a specific edge per-edge wildcard
	// DNS. Without stickiness, two daemon boots
	// against a multi-edge region can land on different edges and the
	// user's previously-created tunnel URLs silently 404.
	//
	// 0 = unknown / first run. edgepicker treats this as a hint: the
	// edge must still be in /v1/edges healthy set or we fall back to the
	// normal active_clients-based selection and surface a switch alert
	// on the SPA so the user knows their old tunnels are temporarily
	// unreachable.
	LastEdgeNodeID int64 `json:"last_edge_node_id,omitempty"`

	// LastEdgeRegion is the region of the edge the daemon dialed on its
	// previous run. Used to classify a reconnect-time edge switch:
	// an INTRA-region switch is transparent (regional DNS keeps the tunnel
	// URL stable + the edge mesh forwards / re-homes the tunnel), so the
	// SPA suppresses the switch banner; only a CROSS-region switch (where
	// the URL's base_domain actually changes) raises it. Empty = unknown /
	// boot.
	LastEdgeRegion string `json:"last_edge_region,omitempty"`

	// PreferPlatformEdge, when true, makes the daemon dial a PLATFORM edge
	// even when the org has its own BYOI edge available. Default false: a
	// BYOI org's daemon defaults to its OWN edge (soft affinity) — and its
	// custom-domain tunnels naturally land there. The customer paid for the
	// plan, so they may always opt back onto the platform data plane.
	//
	// Toggled via `calabi --edge-affinity own|platform`; changing the value
	// clears LastEdgeNodeID/LastEdgeRegion so the next pick re-evaluates from
	// scratch (otherwise the stale region anchor would pin the old edge).
	PreferPlatformEdge bool `json:"prefer_platform_edge,omitempty"`

	// Mode is the client's explicit operating mode, mirroring the edge's
	// top-level `mode`:
	//   "platform" (default; empty) — managed platform: login / daemon sync /
	//       edge discovery go through bff-console; tunnels land on platform edges.
	//   "standalone" — self-hosted: tunnel commands target your own edge
	//       (CALABI_SERVER + CALABI_TOKEN) and you don't expect bff-console. In
	//       this mode `calabi http --ip-deny …` etc. are taken at face value
	//       (no managed-platform warning), since the target edge is your own
	//       `mode: standalone` node.
	// Set via `calabi mode standalone|platform`; overridable per-shell with
	// CALABI_MODE.
	Mode string `json:"mode,omitempty"`
}

// Path returns the resolved credentials file path. Honors $CALABI_CONFIG
// for tests + power users.
func Path() (string, error) {
	if p := os.Getenv("CALABI_CONFIG"); p != "" {
		return p, nil
	}
	dir, err := DataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

// dataDirOverride, when non-empty, replaces the default per-user data dir for
// every calabi data file (creds, local-token, the daemon pidfile). It is set
// once at startup — see SetDataDir, called when the daemon runs as an OS service
// so its files sit next to the executable instead of in the SYSTEM account's
// hard-to-find %LOCALAPPDATA% (…\config\systemprofile\AppData\Local\calabi).
var dataDirOverride string

// SetDataDir overrides the data directory for the rest of this process. Pass ""
// to clear (tests). Must be called before any DataDir/Path consumer.
func SetDataDir(dir string) { dataDirOverride = dir }

// DataDir returns the directory holding calabi's per-machine data files
// (config.json, local-token, calabi.pid). Defaults to <config-dir>/calabi
// (e.g. %LOCALAPPDATA%\calabi); an override set via SetDataDir wins.
func DataDir() (string, error) {
	if dataDirOverride != "" {
		return dataDirOverride, nil
	}
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "calabi"), nil
}

// Load reads the on-disk config; missing file returns an empty Config
// without error (the user is "logged out").
func Load() (*Config, error) {
	p, err := Path()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return nil, fmt.Errorf("read creds: %w", err)
	}
	c := &Config{}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("parse creds (%s): %w", p, err)
	}
	return c, nil
}

// Save writes the config atomically. Creates the parent dir if missing
// and forces 0600 perms on Unix.
// ClearAuth wipes the auth-bearing fields (access_token, refresh_token,
// api_key, device_id, active_org_id) while keeping identity hints the
// SPA can pre-fill (user.email, fingerprint, server).
//
// Use this when the server has signalled a non-recoverable auth state
// for the current install — e.g. the user deleted this device from the
// web console (calabi.err.auth.device_deleted, code 4002). The
// reconnect loop continues to tick but, with no bearer present, every
// dial fails fast and the SPA's /v1/me returns 401 → AuthGate bounces
// the user to /login. They re-authenticate, fresh tokens land in
// creds, and the next tick brings the session back up cleanly with a
// brand-new device row.
//
// We deliberately keep User.Email + Fingerprint:
//   - Email pre-fills the login form so the user sees their context.
//   - Fingerprint is per-install, not auth-bearing; preserving it
//     keeps the "one row per machine" semantics across the re-login.
//   - identity-svc's RegisterClient self-heals any historical
//     soft-deleted row holding this fingerprint, so
//     the next register cycle gets a fresh client_id regardless.
//
// Save error is returned so the caller can decide whether to retry or
// just log + carry on (caller usually wants the latter — even an
// unwritten clear leaves the in-memory token gone for this process,
// which downgrades to a slow-clean on next restart).
func (c *Config) ClearAuth() {
	if c == nil {
		return
	}
	c.AccessToken = ""
	c.RefreshToken = ""
	c.APIKey = ""
	c.DeviceID = 0
	c.ActiveOrgID = 0
}

func Save(c *Config) error {
	p, err := Path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return fmt.Errorf("mkdir creds: %w", err)
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	// Atomic write: tmp -> rename.
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// EnsureFingerprint returns the device's stable fingerprint, generating
// and persisting one if absent. Safe to call from concurrent CLI
// invocations on the same machine (the file write is atomic; the rare
// race might result in two different rows on the server but `calabi
// clients list` will show both rather than corrupt either).
//
// Format: "fp_" + 16 bytes of randomness, hex-encoded — 35 chars total.
// We intentionally don't derive from hostname / mac so privacy-conscious
// users can clear it just by deleting the creds file.
func (c *Config) EnsureFingerprint() (string, error) {
	if c.Fingerprint != "" {
		return c.Fingerprint, nil
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("mint fingerprint: %w", err)
	}
	c.Fingerprint = "fp_" + hex.EncodeToString(b[:])
	if err := Save(c); err != nil {
		return "", fmt.Errorf("save fingerprint: %w", err)
	}
	return c.Fingerprint, nil
}

func configDir() (string, error) {
	if runtime.GOOS == "windows" {
		if d := os.Getenv("LOCALAPPDATA"); d != "" {
			return d, nil
		}
	}
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return d, nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, ".config"), nil
}
