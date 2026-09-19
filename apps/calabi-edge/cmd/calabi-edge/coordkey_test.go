package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/calabi/calabi/apps/calabi-edge/internal/config"
	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

func quietEdgeLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func genCoordKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// In a compose file the edge and the coordinator start together, and the
// coordinator writes its key at its start: the edge waits for the file rather
// than refusing to start — and stops waiting when told to stop.
func TestLoadCoordPubKeyWaitsForTheCoordinatorsFile(t *testing.T) {
	pub, _ := genCoordKey(t)
	path := filepath.Join(t.TempDir(), "shared", "coord.pub")
	go func() {
		time.Sleep(1200 * time.Millisecond)
		_ = os.MkdirAll(filepath.Dir(path), 0o755)
		_ = os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, err := loadCoordPubKey(ctx, config.Config{CoordPubKeyFile: path}, quietEdgeLogger())
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(pub) {
		t.Fatal("read a different key")
	}

	ctx, cancel = context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := loadCoordPubKey(ctx, config.Config{CoordPubKeyFile: filepath.Join(t.TempDir(), "never")}, quietEdgeLogger()); err == nil {
		t.Fatal("waiting did not stop when the context ended")
	}
}

func TestLoadCoordPubKeyInlineAndBad(t *testing.T) {
	pub, _ := genCoordKey(t)
	got, err := loadCoordPubKey(context.Background(), config.Config{CoordPubKey: base64.StdEncoding.EncodeToString(pub)}, quietEdgeLogger())
	if err != nil || !got.Equal(pub) {
		t.Fatalf("inline key: %v", err)
	}
	if got, err := loadCoordPubKey(context.Background(), config.Config{}, quietEdgeLogger()); got != nil || err != nil {
		t.Fatalf("no key configured: %v, %v", got, err)
	}
	for _, bad := range []string{"not base64!", base64.StdEncoding.EncodeToString([]byte("short"))} {
		if _, err := loadCoordPubKey(context.Background(), config.Config{CoordPubKey: bad}, quietEdgeLogger()); err == nil {
			t.Errorf("accepted key %q", bad)
		}
	}
	path := filepath.Join(t.TempDir(), "coord.pub")
	_ = os.WriteFile(path, []byte("garbage"), 0o644)
	if _, err := loadCoordPubKey(context.Background(), config.Config{CoordPubKeyFile: path}, quietEdgeLogger()); err == nil {
		t.Fatal("accepted a garbage key file")
	}
}

// The edge takes this coordinator's grants for self-hosted nodes, and nothing
// else.
func TestCoordGrantsAcceptOnlyThisCoordinatorsGrants(t *testing.T) {
	pub, priv := genCoordKey(t)
	_, otherPriv := genCoordKey(t)
	var node meshproto.NodeKey
	node[0] = 1
	grant := func(k ed25519.PrivateKey, scope meshproto.RelayScope, exp time.Time) []byte {
		g, err := meshproto.SignRelayGrant(k, meshproto.RelayGrant{Node: node, Meshnet: 3, Scope: scope, Expiry: exp})
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	g := coordGrants{pub: pub}
	now := time.Now()
	for _, scope := range []meshproto.RelayScope{meshproto.RelayScopeAll, meshproto.RelayScopeSelfHosted} {
		if rg, err := g.VerifyGrant(grant(priv, scope, now.Add(time.Hour)), now); err != nil || rg.Node != node {
			t.Errorf("scope %s refused: %v", scope, err)
		}
	}
	if _, err := g.VerifyGrant(grant(otherPriv, meshproto.RelayScopeAll, now.Add(time.Hour)), now); err == nil {
		t.Error("another coordinator's grant accepted")
	}
	if _, err := g.VerifyGrant(grant(priv, meshproto.RelayScopeAll, now.Add(-time.Minute)), now); err == nil {
		t.Error("an expired grant accepted")
	}
	if _, err := (coordGrants{}).VerifyGrant(grant(priv, meshproto.RelayScopeAll, now.Add(time.Hour)), now); err == nil {
		t.Error("an edge with no key accepted a grant")
	}
}
