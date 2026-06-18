package main

// wire_community.go is the community-edition control-plane seam: it compiles
// ONLY under `-tags community`, so NONE of the internal/platform/* packages
// (identity / tunnel / quota / cert / config / usage / bff-edge) are linked
// into the binary. A community edge is a pure data plane that trusts the
// client-supplied per-proxy security policy (standalone mode) and never phones
// home. The default build (no tag) is the platform edition.

import (
	"context"
	"log/slog"
)

// edition labels this build for `-version` / startup logs. run() also forces
// mode=standalone when edition == "community" (no control-plane code exists to
// honour platform mode anyway).
const edition = "community"

// wirePlatform is the no-op community implementation: it wires no control
// plane and returns an all-nil bundle, except a bandwidth resolver that still
// honours the EDGE_DEBUG_BANDWIDTH_BPS dev override (handy for local testing).
// The listeners short-circuit every nil dep to their standalone behaviour.
func wirePlatform(_ context.Context, logger *slog.Logger, _ platformInputs) (*platformDeps, error) {
	logger.Info("community edition: control-plane wiring disabled; running standalone data plane")
	return &platformDeps{
		controlPlaneWired: false,
		bandwidthResolver: &quotaBandwidthAdapter{cli: nil, logger: logger},
	}, nil
}
