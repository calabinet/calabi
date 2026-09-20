package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

// The coordinator's relay-grant signing key (R0′).
//
// Its PUBLIC half is what every relay is configured with
// (relay_coord_pubkey), which is why the key is loaded from a FILE and
// bootstrapped only when that file is absent: regenerating it silently would
// invalidate the configuration of every relay in the fleet at once, and the only
// symptom would be nodes quietly failing to connect.
//
// On the platform, unset CALABI_COORD_RELAY_GRANT_KEY_FILE means this
// coordinator issues no grants — the posture until the relays are ready to
// require them.
//
// A self-hosted coordinator always signs, with./coord-grant.key unless told
// otherwise: its edge accepts devices only by this signature, so a self-hosted server
// without a key would have no way to let anyone serve a tunnel. A relay that
// does not require grants ignores them, so signing costs nothing where they are
// not checked.

const (
	relayGrantKeyEnv = "RELAY_GRANT_KEY_FILE"
	// defaultGrantKeyFile is the self-hosted default, in the working directory
	// like the self-signed certificate's./coord-tls.
	defaultGrantKeyFile = "coord-grant.key"
	// grantPubkeyFileEnv names a file the coordinator (re)writes with the public
	// half at start — for an edge that reads it from a volume the two share.
	grantPubkeyFileEnv = "GRANT_PUBKEY_FILE"
)

// relayGrantIssuer builds the netmap's grant issuer, or nil when no key file is
// configured on the platform. It exits the process on a broken key: a
// coordinator that cannot sign is one whose nodes will be turned away by every
// relay and edge that requires a grant, and discovering that from connection
// failures is far worse than refusing to start.
func relayGrantIssuer(logger *slog.Logger, scope func(context.Context, *core.Node) meshproto.RelayScope, selfHosted bool) core.RelayGrantIssuer {
	path := env(relayGrantKeyEnv)
	if path == "" && selfHosted {
		path = defaultGrantKeyFile
	}
	if path == "" {
		logger.Info("coord: relay grants disabled (no " + envPrefix + "_" + relayGrantKeyEnv + ")")
		return nil
	}
	key, created, err := loadOrCreateRelayGrantKey(path)
	if err != nil {
		logger.Error("coord: relay grant key unusable", "path", path, "err", err)
		os.Exit(1)
	}
	pub := base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	if created {
		logger.Warn("coord: generated a NEW grant signing key; every edge and relay must be configured with this public key",
			"path", path, "relay_coord_pubkey", pub)
	} else {
		logger.Info("coord: grants enabled", "relay_coord_pubkey", pub)
	}
	if out := env(grantPubkeyFileEnv); out != "" {
		if err := writeGrantPubkey(out, pub); err != nil {
			logger.Error("coord: could not write the grant public key", "path", out, "err", err)
			os.Exit(1)
		}
		logger.Info("coord: wrote the grant public key for edges that read it", "path", out)
	}
	return &core.SigningRelayGrantIssuer{Key: key, Scope: scope}
}

// writeGrantPubkey writes the public key where an edge reads it: whole or not
// at all, so an edge starting at the same moment never reads half a key.
func writeGrantPubkey(path, pub string) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(pub+"\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// loadOrCreateRelayGrantKey reads the base64 seed at path, or writes a fresh one
// if the file does not exist. An existing but unreadable file is an ERROR, never
// a reason to generate: overwriting it would rotate the key behind the
// operator's back.
func loadOrCreateRelayGrantKey(path string) (ed25519.PrivateKey, bool, error) {
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		seed, decErr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if decErr != nil {
			return nil, false, fmt.Errorf("decode seed: %w", decErr)
		}
		if len(seed) != ed25519.SeedSize {
			return nil, false, fmt.Errorf("seed is %d bytes, want %d", len(seed), ed25519.SeedSize)
		}
		return ed25519.NewKeyFromSeed(seed), false, nil
	case !os.IsNotExist(err):
		return nil, false, fmt.Errorf("read: %w", err)
	}

	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, false, fmt.Errorf("generate seed: %w", err)
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, false, fmt.Errorf("create dir: %w", err)
		}
	}
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(seed)+"\n"), 0o600); err != nil {
		return nil, false, fmt.Errorf("write: %w", err)
	}
	return ed25519.NewKeyFromSeed(seed), true, nil
}

// runPubkey is `calabi-coord pubkey`: the public half of the grant signing key,
// which every edge and relay of this server is configured with. It reads the key
// the coordinator uses — run it where the coordinator runs, with its
// environment — and never creates one: a key made here would not be the one
// the coordinator signs with.
func runPubkey() int {
	path := env(relayGrantKeyEnv)
	if path == "" {
		if env("IDENTITY_ADDR") != "" {
			fmt.Fprintln(os.Stderr, "calabi-coord pubkey: this coordinator signs nothing unless "+envPrefix+"_"+relayGrantKeyEnv+" is set")
			return 1
		}
		path = defaultGrantKeyFile
	}
	pub, err := readGrantPubkey(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "calabi-coord pubkey:", err)
		return 1
	}
	fmt.Println(pub)
	return 0
}

// readGrantPubkey is the public half of the key at path, base64. It only reads.
func readGrantPubkey(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("no key at %s: start the coordinator first (it makes one), or run this in its working directory", path)
		}
		return "", err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return "", fmt.Errorf("%s is not a grant key", path)
	}
	return base64.StdEncoding.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)), nil
}
