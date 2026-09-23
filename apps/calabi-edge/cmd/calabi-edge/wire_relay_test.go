package main

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/calabinet/calabi/apps/calabi-edge/internal/config"
)

// A relay with no control plane has nowhere to send its usage. Until 1.13 it got
// a reporter anyway, with a nil bus, and the first minute that carried traffic
// panicked in relayUsageReporter.record — a standalone relay started the way
// docs/self-hosting.md shows (CALABI_EDGE_ROLE=mesh CALABI_EDGE_RELAY_LABEL=home)
// crashed about a minute after a device first used it.
func TestStandaloneRelayGetsNoUsageReporter(t *testing.T) {
	for _, role := range []string{"relay", "both"} {
		t.Run(role, func(t *testing.T) {
			cfg := config.Default()
			cfg.Role = role
			cfg.Mesh.Label = "home"
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			deps, err := wirePlatform(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), platformInputs{cfg: cfg})
			if err != nil {
				t.Fatalf("wirePlatform: %v", err)
			}
			if deps.controlPlaneWired {
				t.Fatal("test setup: this config should have no control plane")
			}
			if deps.relayReporter != nil {
				t.Fatal("a relay with no control plane got a usage reporter; it has no bus to publish on and panics on its first report")
			}
		})
	}
}
