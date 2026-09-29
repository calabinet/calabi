package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// How a node's own relay on calabi.net learns whom to admit.
//
// Such a relay is its organization's: it registers itself into that
// organization's mesh through bff-edge (runRelayRegistrar), and only that
// organization's devices are told it exists. Being listed there is not the same
// as admitting only them, though. The relay is a public TCP port: one that does
// not check grants relays for whoever reaches it, and lets anyone claiming a
// device's key (every member reads them in the netmap) take that device's link.
//
// Checking grants needs the key the platform coordinator signs them with. The
// relay has exactly one conversation with the platform in which to learn it:
// the answer to its own registration, which carries it (RegisterRelayResponse
// coord_grant_pubkey). relayAdmission is where that answer lands, and where
// runRelay reads it.
//
// The answer, not the relay, decides. An empty key means the platform signs no
// grants — its devices then hold none, and a relay demanding one would turn all
// of them away — so the relay admits devices without one, and says so. That is
// also what a gateway older than the field answers, which is what makes the
// rollout order-free: nothing here can black-hole a relay that worked before.

// relayGrantKeyFile is where a relay keeps the last key its registration heard,
// under state.dir, so that a restart while the platform cannot be reached (an
// outage, a broken gateway) starts it checking grants at once instead of
// leaving it down until the platform answers.
const relayGrantKeyFile = "relay-grant.pub"

// relayAdmission holds the latest answer a relay's registration got about
// admitting devices.
type relayAdmission struct {
	logger *slog.Logger
	// keyFile persists the key across restarts; "" when there is no state.dir.
	keyFile string

	mu    sync.Mutex
	heard bool              // a registration has answered since this process started
	key   ed25519.PublicKey // nil: the platform signs no grants
	// changed is closed, and replaced, whenever the answer changes.
	changed chan struct{}
	// noRegistration says why this relay cannot register at all, so that its
	// wait for an answer that will never come explains itself.
	noRegistration string
}

func newRelayAdmission(stateDir string, logger *slog.Logger) *relayAdmission {
	a := &relayAdmission{logger: logger, changed: make(chan struct{})}
	if dir := strings.TrimSpace(stateDir); dir != "" {
		a.keyFile = filepath.Join(dir, relayGrantKeyFile)
	}
	return a
}

// learn records one registration's answer: the platform's grant key, or none.
// A malformed key is an error and changes nothing — the relay keeps admitting
// the way it did.
func (a *relayAdmission) learn(raw []byte) error {
	var key ed25519.PublicKey
	switch len(raw) {
	case 0:
	case ed25519.PublicKeySize:
		key = append(ed25519.PublicKey(nil), raw...)
	default:
		return fmt.Errorf("the platform's grant key is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	a.mu.Lock()
	if a.heard && bytes.Equal(a.key, key) {
		a.mu.Unlock()
		return nil
	}
	a.heard, a.key = true, key
	close(a.changed)
	a.changed = make(chan struct{})
	a.mu.Unlock()
	a.remember(key)
	return nil
}

// cannotRegister records that this relay's registration is not wired, and why.
func (a *relayAdmission) cannotRegister(why string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.noRegistration = why
}

// unregistrable is the reason cannotRegister gave, or "".
func (a *relayAdmission) unregistrable() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.noRegistration
}

// current is the latest answer (heard=false before the first one), and a channel
// that is closed when it next changes.
func (a *relayAdmission) current() (heard bool, key ed25519.PublicKey, changed <-chan struct{}) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.heard, a.key, a.changed
}

// remembered is the key a previous run heard, or nil. Read once, at start: from
// then on the platform's answers decide.
func (a *relayAdmission) remembered() ed25519.PublicKey {
	if a.keyFile == "" {
		return nil
	}
	raw, err := os.ReadFile(a.keyFile)
	if err != nil {
		if !os.IsNotExist(err) {
			a.logger.Warn("mesh relay: could not read the grant key kept from the last run", "file", a.keyFile, "err", err)
		}
		return nil
	}
	key, err := parseCoordPubKey(strings.TrimSpace(string(raw)))
	if err != nil {
		a.logger.Warn("mesh relay: ignoring the grant key kept from the last run", "file", a.keyFile, "err", err)
		return nil
	}
	return key
}

// remember keeps key for the next start, or forgets the kept one when the
// platform answered with none: a stale key would turn away devices that have
// no grant to present.
func (a *relayAdmission) remember(key ed25519.PublicKey) {
	if a.keyFile == "" {
		return
	}
	if key == nil {
		if err := os.Remove(a.keyFile); err != nil && !os.IsNotExist(err) {
			a.logger.Warn("mesh relay: could not remove the kept grant key", "file", a.keyFile, "err", err)
		}
		return
	}
	if err := writeFileAtomic(a.keyFile, []byte(base64.StdEncoding.EncodeToString(key)+"\n")); err != nil {
		a.logger.Warn("mesh relay: could not keep the grant key for the next start; a restart while calabi.net is unreachable will wait for it",
			"file", a.keyFile, "err", err)
	}
}

// writeFileAtomic writes whole or not at all, so a crash mid-write never leaves
// half a key for the next start to trip over.
func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
