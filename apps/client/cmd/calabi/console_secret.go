package main

// The local console's unlock secret: what a visitor who is NOT on this machine
// must enter before the console's /v1 API answers them
// internal/status/console_unlock.go for how it is enforced).
//
// Callers on this machine never need it — the desktop shell and a local browser
// are the console's owners. Everyone else does, and that is what makes binding
// the console beyond loopback reasonable at all: it hands its write token to
// whoever can load the page.

import (
	"crypto/rand"
	"encoding/base32"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/calabi/calabi/apps/client/internal/creds"
	"github.com/calabi/calabi/apps/client/internal/status"
)

// consoleSecretFile is where a generated secret is kept: the data directory,
// beside the local token, so a second client on the machine (its own data dir)
// has its own secret, and a service's is protected like the rest of its files.
const consoleSecretFile = "console-secret"

// shortConsoleSecret is the length below which a chosen secret earns a warning.
// Guesses are rate-limited, so a short one is not free to find, but a generated
// secret is 120 bits and there is no reason to settle for much less.
const shortConsoleSecret = 12

// resolveConsoleSecret returns the secret and where it came from:
//   - "env":       CALABI_STATUS_SECRET — the operator chose it;
//   - "file":      generated on an earlier run and kept;
//   - "generated": fresh, and now saved for the next run.
//
// A generated secret is kept rather than rolled on every start: a secret that
// changed with each restart would lock out whoever just learned it, and for a
// service the only place to learn it again is a log. To roll it, delete the
// file and restart.
func resolveConsoleSecret() (secret, source, path string, err error) {
	if v := strings.TrimSpace(os.Getenv("CALABI_STATUS_SECRET")); v != "" {
		return v, "env", "", nil
	}
	dir, err := creds.DataDir()
	if err != nil {
		return "", "", "", err
	}
	path = filepath.Join(dir, consoleSecretFile)
	if b, rerr := os.ReadFile(path); rerr == nil {
		if v := strings.TrimSpace(string(b)); v != "" {
			return v, "file", path, nil
		}
	}
	if secret, err = newConsoleSecret(); err != nil {
		return "", "", "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", "", err
	}
	// Best-effort, like every other write into this directory (audit ACL-1).
	defer func() { _ = creds.SecureDataDir() }()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(secret+"\n"), 0o600); err != nil {
		return "", "", "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", "", "", err
	}
	return secret, "generated", path, nil
}

// newConsoleSecret is 120 random bits as four groups of six base32 letters and
// digits — long enough not to be guessed, short enough to type from a log.
func newConsoleSecret() (string, error) {
	var b [15]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	s := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:]))
	return s[0:6] + "-" + s[6:12] + "-" + s[12:18] + "-" + s[18:24], nil
}

// configureConsoleUnlock arms srv with the unlock secret and says where to find
// it. If the secret cannot be set up, remote visitors stay refused outright — the
// console is still fully usable from this machine.
func configureConsoleUnlock(logger *slog.Logger, srv *status.Server, bindAddr string) {
	secret, source, path, err := resolveConsoleSecret()
	if err != nil {
		logger.Warn("console: visitors from other machines stay refused — could not set up the unlock secret", "err", err)
		return
	}
	srv.SetConsoleSecret(secret)
	host, _, _ := net.SplitHostPort(bindAddr)
	switch {
	case source == "env":
		if len(secret) < shortConsoleSecret {
			logger.Warn("console: CALABI_STATUS_SECRET is short — guesses are rate-limited, but a longer secret costs nothing",
				"length", len(secret))
		}
		logger.Info("console: visitors from other machines must enter the unlock secret set in CALABI_STATUS_SECRET")
	case !isLoopbackHost(host):
		// The one set-up where somebody is about to need it — and for a container
		// the log is the only place they can read it. So print it, not just the
		// file it is in.
		logger.Warn("console: listening beyond this machine — visitors from other machines must enter this unlock secret",
			"secret", secret, "stored_in", path)
	default:
		logger.Debug("console: visitors from other machines (e.g. through a reverse proxy) must enter the unlock secret",
			"stored_in", path)
	}
}
