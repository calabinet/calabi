package config

import (
	"fmt"
	"os"
	"strings"
)

// prodguard.go — refuse to run a PRODUCTION edge in a degraded posture
// (full-oss-plan F0.2, the edge half of coord's cmd/calabi-coord/prodguard.go).
//
// The edge's fallbacks are deliberate and correct for their intended use: a
// relay that does not require grants is how the fleet was rolled out before R0′
// was switched on. What makes them dangerous is that nothing distinguishes "I
// meant this" from "my control plane vanished and I silently became a simpler,
// more trusting server" — and once the source is public, that distinction is
// exactly what an attacker probes.
//
// (There used to be a sharper case: a demo token in Default(), printed in the
// public tree, accepted by any edge run without a config file. The static token
// table it lived in is gone —

// IsProduction reports whether this process claims a production deployment.
// Same signal as coord: CALABI_ENV, set in the compose file itself so a
// deployment is production by construction rather than by an operator
// remembering to add a line.
func IsProduction() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("CALABI_ENV"))) {
	case "production", "prod":
		return true
	}
	return false
}

// ValidateProductionPosture returns an error naming EVERY active fail-open
// fallback (not just the first, so one restart shows the whole list). Returns
// nil outside production, so dev and self-hosted deployments are untouched.
//
// Call it AFTER NormalizeForMode: standalone normalization is what makes
// "no control plane" a stated intent rather than an accident.
func (c Config) ValidateProductionPosture() error {
	if !IsProduction() {
		return nil
	}
	var bad []string

	// 1. No control plane where one was meant. A platform-mode node without
	// bff-edge verifies nobody against identity-svc; for a node serving tunnels
	// ValidateClientAuth already refuses it, and this names it for a relay too.
	if !c.IsStandaloneMode() && !c.MultiRegion.IsBFFEdge() {
		bad = append(bad, "platform mode without a bff-edge connection: every edge reaches the control plane "+
			"through bff-edge (F3 step 2b), so nothing here would check who a client is (set multi_region, or "+
			"say mode: standalone with the coordinator's key if this node belongs to a self-hosted coordinator)")
	}

	// 2. A platform relay that accepts ungranted clients. kind=platform means
	// coord advertises this node in the PLATFORM DERP map, so without grant
	// verification it relays for anyone who finds it — traffic that is neither
	// attributable to an org nor stoppable when one is over quota.
	if c.ServesMesh() && c.Mesh.IsPlatformKind() && !c.Mesh.RequireAuth {
		bad = append(bad, "relay.kind=platform with relay.require_auth=false: this node is advertised in the "+
			"platform DERP map but would relay for any client, attributable to no org (set relay.require_auth "+
			"with relay.coord_pubkey)")
	}

	if len(bad) == 0 {
		return nil
	}
	return fmt.Errorf("CALABI_ENV=production but %d fail-open fallback(s) would be active:\n  - %s",
		len(bad), strings.Join(bad, "\n  - "))
}
