package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"
	"time"

	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
)

// selfHostedAuth is the Authenticator of a coordinator with no identity service:
// the operator's key file, or the dev key (devStaticAuth), plus the keys the
// coordinator mints itself (`calabi-coord invite`, core/authkeys.go).
func selfHostedAuth(logger *slog.Logger, keys core.AuthKeyStore, durable bool) (core.Authenticator, error) {
	static, err := devStaticAuth(durable)
	if err != nil {
		return nil, err
	}
	switch {
	case env("AUTHKEYS_FILE") != "":
		logger.Info("coord auth: the key file plus keys minted with calabi-coord invite", "file", env("AUTHKEYS_FILE"))
	case static != nil:
		logger.Warn("coord auth: no CALABI_COORD_AUTHKEYS_FILE and no database, so the BUILT-IN dev key admits any caller into meshnet 1 (NOT for production); keys minted with calabi-coord invite work too")
	default:
		logger.Info("coord auth: no key file; devices join with keys minted by calabi-coord invite")
	}
	return &core.KeyAuth{Static: static, Keys: keys}, nil
}

// devStaticAuth builds the key-file half of a self-hosted coordinator's auth.
// Sources, first match:
//   - CALABI_COORD_AUTHKEYS_FILE: a JSON map of auth-key -> {meshnet, tags}. This is
//     the self-hosted coordinator's real shape (multi-key + ACL tags); loaded when
//     set. Example:
//     { "key-a": { "meshnet": 1, "tags": ["tag:eng"] }, "key-b": { "meshnet": 1 } }
//   - a coordinator with a database (durable): none. It is a real deployment,
//     and its devices join with keys it mints (calabi-coord invite); a key
//     printed in the public source has no business admitting anyone there.
//   - else: a single key from CALABI_COORD_DEV_AUTH_KEY (default "dev-meshnet-1-key")
//     mapped to meshnet 1 with no tags — the zero-config dev/smoke path.
//
// The platform build uses an identity-svc Authenticator (tk_ keys -> org)
// instead — see wire_platform.go.
func devStaticAuth(durable bool) (core.Authenticator, error) {
	if path := env("AUTHKEYS_FILE"); path != "" {
		a, err := newFileAuth(path)
		if err != nil {
			// Setting AUTHKEYS_FILE states the intent "these keys, and only
			// these". Falling back to the built-in key on an unreadable or
			// half-written file answered that with "anyone, into meshnet 1" —
			// using a key that is printed in the public source (audit finding
			// MESH-10). prodguard only checks that the variable is SET, so an
			// unmounted volume or a typo sailed straight past it.
			//
			// Fail hard regardless of environment: a broken key file is never a
			// reason to admit the world.
			return nil, fmt.Errorf("CALABI_COORD_AUTHKEYS_FILE=%s could not be loaded (%w) — "+
				"refusing to start rather than fall back to the built-in dev key", path, err)
		}
		return a, nil
	}
	if durable {
		return nil, nil
	}
	key := env("DEV_AUTH_KEY")
	if key == "" {
		key = "dev-meshnet-1-key"
	}
	return core.StaticAuth{Keys: map[string]core.Identity{key: {Meshnet: 1}}}, nil
}

// loadStaticAuth reads a JSON auth-keys file (key -> {meshnet, tags}) into a
// StaticAuth.
func loadStaticAuth(path string) (core.StaticAuth, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return core.StaticAuth{}, err
	}
	var m map[string]struct {
		Meshnet int64    `json:"meshnet"`
		Tags    []string `json:"tags"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return core.StaticAuth{}, err
	}
	keys := make(map[string]core.Identity, len(m))
	for k, v := range m {
		// An empty key would admit a node that sends none; a meshnet of 0 is no
		// meshnet. Both are a file that means something other than it says.
		if k == "" {
			return core.StaticAuth{}, errors.New("an empty key")
		}
		if v.Meshnet <= 0 {
			return core.StaticAuth{}, fmt.Errorf("a key with meshnet %d (want 1 or more)", v.Meshnet)
		}
		keys[k] = core.Identity{Meshnet: core.MeshnetID(v.Meshnet), Tags: v.Tags}
	}
	return core.StaticAuth{Keys: keys}, nil
}

// fileAuth is the auth-keys file, followed as it changes: adding or removing a
// key no longer needs a restart.
// The first load failing stops the coordinator (devStaticAuth); a later edit
// that does not parse keeps the keys already loaded and says so loudly, as the
// ACL file does and as the edge does with its tokens.
type fileAuth struct {
	path string
	keys atomic.Pointer[core.StaticAuth]
	mod  time.Time // the file's mtime at the last load; the watcher's alone
}

// authKeysFile is the loaded file, for startAuthKeysWatcher; nil when keys do
// not come from a file.
var authKeysFile *fileAuth

func newFileAuth(path string) (*fileAuth, error) {
	a := &fileAuth{path: path, mod: fileModTime(path)}
	keys, err := loadStaticAuth(path)
	if err != nil {
		return nil, err
	}
	a.keys.Store(&keys)
	authKeysFile = a
	return a, nil
}

func (a *fileAuth) Resolve(ctx context.Context, authKey string) (core.Identity, error) {
	return a.keys.Load().Resolve(ctx, authKey)
}

// Reauthorize is StaticAuth's: a key in the file admits a device, and taking
// it out does not remove the devices it admitted.
func (a *fileAuth) Reauthorize(ctx context.Context, meshnet core.MeshnetID, principal string) error {
	return a.keys.Load().Reauthorize(ctx, meshnet, principal)
}

// Spend is StaticAuth's: file keys have no uses to count.
func (a *fileAuth) Spend(ctx context.Context, principal string) (func(), error) {
	return a.keys.Load().Spend(ctx, principal)
}

// reload re-reads the file if it changed since the last look. It reports what
// happened for the log: changed is false when there was nothing to do.
func (a *fileAuth) reload() (changed bool, n int, err error) {
	m := fileModTime(a.path)
	if m.Equal(a.mod) {
		return false, 0, nil
	}
	a.mod = m
	keys, err := loadStaticAuth(a.path)
	if err != nil {
		return true, 0, err
	}
	a.keys.Store(&keys)
	return true, len(keys.Keys), nil
}

// startAuthKeysWatcher polls the auth-keys file every 2 seconds. No-op when the
// keys do not come from a file.
func startAuthKeysWatcher(logger *slog.Logger) {
	a := authKeysFile
	if a == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			switch changed, n, err := a.reload(); {
			case !changed:
			case err != nil:
				logger.Error("auth-keys file reload failed; KEEPING THE PREVIOUS KEYS — a key removed in this edit still works until the file loads", "path", a.path, "err", err)
			default:
				// Enrolled devices are not affected either way: a key admits a
				// device, and removing it does not remove the device.
				logger.Info("auth-keys file reloaded", "path", a.path, "keys", n)
			}
		}
	}()
}
