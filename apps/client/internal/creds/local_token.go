// local_token.go — the per-daemon-instance bearer secret that gates the
// status server's WRITE endpoints (POST /v1/tunnels, etc., added).
//
// Why a separate file from creds Config?
//
//   - Lifecycle: regenerated on every `calabi daemon` start. Stale
//     tokens from a previous run must NOT be valid — the safest way to
//     enforce that is "overwrite the file at boot" rather than "ttl-check
//     on every request".
//   - Trust model: the token is the bridge between the local UI (browser
//     loaded from http://127.0.0.1:7400) and the daemon. The UI reads
//     the token by fetch()'ing /v1/local-token from the same origin —
//     loopback bind plus the OS-level file permission (0600) is enough
//     under our "any user with access to this account is the owner" model.
//   - Privacy: NOT in config.json, which the user might paste verbatim
//     in a bug report. Separate file = harder to accidentally leak.
//
// Format: 64 hex chars (32 bytes of randomness). Length matches a
// typical SHA256, which is what a security-paranoid reader will assume
// it is — encourages treating it as a secret.
package creds

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const localTokenFilename = "local_token"

// LocalTokenPath returns the resolved file location. Mirrors Path() but
// uses a different basename so an operator running `cat config.json`
// doesn't blow the secret onto their screen.
func LocalTokenPath() (string, error) {
	if p := os.Getenv("CALABI_LOCAL_TOKEN"); p != "" {
		return p, nil
	}
	dir, err := DataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, localTokenFilename), nil
}

// MintLocalToken generates a fresh 32-byte token, writes it to disk
// with 0600 perms, and returns the hex-encoded value. Used by daemon
// boot; subsequent calls regenerate.
func MintLocalToken() (string, error) {
	p, err := LocalTokenPath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return "", fmt.Errorf("mkdir local-token: %w", err)
	}
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("mint local-token: %w", err)
	}
	tok := hex.EncodeToString(b[:])
	// Atomic write — UI may already be polling and we don't want a
	// torn read of half the file.
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, []byte(tok), 0o600); err != nil {
		return "", fmt.Errorf("write local-token: %w", err)
	}
	if err := os.Rename(tmp, p); err != nil {
		return "", fmt.Errorf("install local-token: %w", err)
	}
	return tok, nil
}

// LoadLocalToken reads the current token; ErrNoLocalToken if absent.
// The UI calls this via the /v1/local-token endpoint; CLI tests use
// it directly to construct authenticated requests.
func LoadLocalToken() (string, error) {
	p, err := LocalTokenPath()
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return "", ErrNoLocalToken
		}
		return "", fmt.Errorf("read local-token: %w", err)
	}
	tok := string(b)
	// Strip trailing newline if a user hand-edited; otherwise validate.
	if len(tok) > 0 && tok[len(tok)-1] == '\n' {
		tok = tok[:len(tok)-1]
	}
	if len(tok) == 0 {
		return "", ErrNoLocalToken
	}
	return tok, nil
}

// CompareLocalToken constant-time-compares got against the on-disk
// token. Returns true iff they match. Always reads from disk so a token
// rotation (next daemon boot) takes effect without a cache flush.
func CompareLocalToken(got string) bool {
	want, err := LoadLocalToken()
	if err != nil || want == "" || got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}

// ErrNoLocalToken means the daemon hasn't started yet (or someone deleted
// the file). Callers usually translate this to a 503 "daemon not ready".
var ErrNoLocalToken = errors.New("local-token file missing (daemon not running?)")
