package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/calabinet/calabi/apps/calabi-edge/internal/config"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

// The coordinator this edge belongs to. Its public key is how a standalone edge accepts anyone: devices present
// the grant the coordinator signed, for tunnels and relay alike.

// coordKeyWaitLog is how often loadCoordPubKey says it is still waiting.
const coordKeyWaitLog = 30 * time.Second

// loadCoordPubKey returns the coordinator's key, inline or from the file the
// coordinator writes. A file that does not exist yet is waited for: in a compose
// file the two start together, and the coordinator writes the file at its start.
// nil, nil when neither is configured (a platform edge).
func loadCoordPubKey(ctx context.Context, cfg config.Config, logger *slog.Logger) (ed25519.PublicKey, error) {
	if s := strings.TrimSpace(cfg.CoordPubKey); s != "" {
		return parseCoordPubKey(s)
	}
	path := strings.TrimSpace(cfg.CoordPubKeyFile)
	if path == "" {
		return nil, nil
	}
	waiting := time.Time{}
	for {
		raw, err := os.ReadFile(path)
		switch {
		case err == nil && strings.TrimSpace(string(raw)) != "":
			key, perr := parseCoordPubKey(strings.TrimSpace(string(raw)))
			if perr != nil {
				return nil, fmt.Errorf("coord_pubkey_file %s: %w", path, perr)
			}
			return key, nil
		case err != nil && !os.IsNotExist(err):
			return nil, fmt.Errorf("coord_pubkey_file %s: %w", path, err)
		}
		if time.Since(waiting) >= coordKeyWaitLog {
			logger.Info("waiting for the coordinator to write its public key", "coord_pubkey_file", path)
			waiting = time.Now()
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

func parseCoordPubKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("the coordinator's key is not base64: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("the coordinator's key is %d bytes, want %d", len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

// coordGrants is session.GrantAuth for a standalone edge: the grant must carry
// its coordinator's signature, be valid now, and be good for a self-hosted node.
type coordGrants struct {
	pub ed25519.PublicKey
}

func (g coordGrants) VerifyGrant(grant []byte, now time.Time) (meshproto.RelayGrant, error) {
	if len(g.pub) != ed25519.PublicKeySize {
		return meshproto.RelayGrant{}, errors.New("this edge has no coordinator key")
	}
	rg, err := meshproto.VerifyRelayGrant(g.pub, grant, now)
	if err != nil {
		return meshproto.RelayGrant{}, err
	}
	if !rg.Scope.Permits(meshproto.RelayKindSelfHosted) {
		return meshproto.RelayGrant{}, fmt.Errorf("grant scope %s does not cover this edge", rg.Scope)
	}
	return rg, nil
}
