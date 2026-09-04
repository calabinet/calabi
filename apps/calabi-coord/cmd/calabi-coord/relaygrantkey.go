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

	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// The coordinator's relay-grant signing key (R0′).
//
// Its PUBLIC half is what every relay is configured with
// (relay_coord_pubkey), which is why the key is loaded from a FILE and
// bootstrapped only when that file is absent: regenerating it silently would
// invalidate the configuration of every relay in the fleet at once, and the only
// symptom would be nodes quietly failing to connect.
//
// Unset CALABI_COORD_RELAY_GRANT_KEY_FILE means this coordinator issues no grants.
// That is the correct posture until the relays are ready to require them —

const relayGrantKeyEnv = "RELAY_GRANT_KEY_FILE"

// relayGrantIssuer builds the netmap's grant issuer, or nil when no key file is
// configured. It exits the process on a broken key: a coordinator that cannot
// sign is one whose nodes will be turned away by every relay that requires a
// grant, and discovering that from connection failures is far worse than
// refusing to start.
func relayGrantIssuer(logger *slog.Logger, scope func(context.Context, *core.Node) meshproto.RelayScope) core.RelayGrantIssuer {
	path := env(relayGrantKeyEnv)
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
		logger.Warn("coord: generated a NEW relay grant key; every relay must be configured with this public key",
			"path", path, "relay_coord_pubkey", pub)
	} else {
		logger.Info("coord: relay grants enabled", "relay_coord_pubkey", pub)
	}
	return &core.SigningRelayGrantIssuer{Key: key, Scope: scope}
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
