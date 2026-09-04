package main

// meshacceptroutes_test.go — the upgrade seed for consumer-side route acceptance.
//
// The default is OFF, because a peer's advertised route lands in THIS machine's
// kernel routing table and can hijack the return path of connections to services
// this machine publishes. But flipping a default under a node that already uses
// subnet routes would silently cut traffic that works today — the same trap the
// coordinator's route approval already avoided for advertisers.
//
// So the first run decides by asking whether this node has meshed before (an
// existing WireGuard key = an upgrade) and WRITES THE ANSWER DOWN. The write is
// the whole point: the key file appears as soon as the node meshes once, so
// re-deriving the answer later would flip a fresh node's default on its second
// boot.

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/calabi/calabi/apps/client/internal/creds"
)

func quietTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// isolateCreds points creds at a fresh file and returns a key-file path that
// does NOT exist yet.
func isolateCreds(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("CALABI_CONFIG", filepath.Join(dir, "config.json"))
	return filepath.Join(dir, "mesh.key")
}

func writeKey(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("not-a-real-key"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
}

func storedAccept(t *testing.T) *bool {
	t.Helper()
	c, err := creds.Load()
	if err != nil {
		t.Fatalf("load creds: %v", err)
	}
	return c.MeshAcceptRoutes
}

func TestResolveAcceptRoutesSeedsFromPriorEnrollment(t *testing.T) {
	t.Run("an already-meshed node keeps accepting", func(t *testing.T) {
		key := isolateCreds(t)
		writeKey(t, key) // this node has meshed before → an upgrade

		if !resolveAcceptRoutes(nil, key, quietTestLogger()) {
			t.Fatal("an upgraded node stopped accepting routes — that silently cuts working subnet routers")
		}
		if got := storedAccept(t); got == nil || !*got {
			t.Fatalf("seed not persisted as true: %v", got)
		}
	})

	t.Run("a fresh node starts closed", func(t *testing.T) {
		key := isolateCreds(t) // no key on disk → never meshed

		if resolveAcceptRoutes(nil, key, quietTestLogger()) {
			t.Fatal("a fresh node accepted routes; the default is off")
		}
		if got := storedAccept(t); got == nil || *got {
			t.Fatalf("seed not persisted as false: %v", got)
		}
	})

	// The trap the persistence exists for. A fresh node seeds false, then meshes
	// (creating the key). If the answer were re-derived from the key file instead
	// of read back from creds, the next boot would silently turn acceptance ON.
	t.Run("the seed survives the node meshing for the first time", func(t *testing.T) {
		key := isolateCreds(t)
		if resolveAcceptRoutes(nil, key, quietTestLogger()) {
			t.Fatal("first boot should be closed")
		}
		writeKey(t, key) // the node has now meshed once

		if resolveAcceptRoutes(nil, key, quietTestLogger()) {
			t.Fatal("the default flipped on the second boot — the seed is not being read back")
		}
	})
}

func TestResolveAcceptRoutesRespectsAnExplicitChoice(t *testing.T) {
	yes, no := true, false

	t.Run("a config-file value wins over everything", func(t *testing.T) {
		key := isolateCreds(t) // no key → the seed would say false
		if !resolveAcceptRoutes(&yes, key, quietTestLogger()) {
			t.Fatal("explicit true was ignored")
		}
		// An explicit setting must not be written into creds: the file owns it, and
		// persisting it would strand the value after the file changes.
		if got := storedAccept(t); got != nil {
			t.Fatalf("explicit choice leaked into creds: %v", *got)
		}
	})

	t.Run("an explicit false overrides an upgraded node's seed", func(t *testing.T) {
		key := isolateCreds(t)
		writeKey(t, key) // would otherwise seed true
		if resolveAcceptRoutes(&no, key, quietTestLogger()) {
			t.Fatal("explicit false was ignored")
		}
	})

	t.Run("a stored choice wins over the enrollment signal", func(t *testing.T) {
		key := isolateCreds(t)
		writeKey(t, key) // would otherwise seed true
		c, err := creds.Load()
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		c.MeshAcceptRoutes = &no
		if err := creds.Save(c); err != nil {
			t.Fatalf("save: %v", err)
		}
		if resolveAcceptRoutes(nil, key, quietTestLogger()) {
			t.Fatal("the user's stored choice was overwritten by the seed")
		}
	})
}

// routePolicy turns the runner's settings into the mesh policy. A malformed
// exclusion must not take the session down with it — the safe reading of "I
// can't parse your exclusion" is to keep the rest of the policy working.
func TestRoutePolicySkipsUnparseableExclusions(t *testing.T) {
	key := isolateCreds(t)
	writeKey(t, key)
	r := &meshRunner{
		logger: quietTestLogger(),
		cfg: meshConfig{
			KeyFile:       key,
			RouteExcludes: []string{"192.168.1.22/32", "not-a-cidr", "  ", "10.0.0.0/8"},
		},
	}
	p := r.routePolicy()
	if !p.Accept {
		t.Fatal("an upgraded node should still accept")
	}
	if len(p.Excludes) != 2 {
		t.Fatalf("excludes = %v, want the two parseable ones", p.Excludes)
	}
	if p.Excludes[0].String() != "192.168.1.22/32" || p.Excludes[1].String() != "10.0.0.0/8" {
		t.Fatalf("excludes = %v", p.Excludes)
	}
}
