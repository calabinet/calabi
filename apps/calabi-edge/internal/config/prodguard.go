package config

import (
	"fmt"
	"os"
	"strings"
)

// prodguard.go — refuse to run a PRODUCTION edge in a degraded posture
// (full-oss-plan F0.2, the edge half of coord's cmd/calabi-coord/prodguard.go).
//
// The edge's fallbacks are deliberate and correct for their intended use: no
// identity-svc means "verify clients against the static accepted_tokens table"
// (that IS standalone/self-hosted mode), and a relay that does not require grants
// is how the fleet was rolled out before R0′ was switched on. What makes them
// dangerous is that nothing distinguishes "I meant this" from "my control plane
// vanished and I silently became a simpler, more trusting server" — and once
// the source is public, that distinction is exactly what an attacker probes.
//
// PlaceholderToken below is the sharpest case: it ships in Default(), so an
// edge that never had its config filled in accepts a token printed in the
// public repository.

// PlaceholderToken is the self-describing dev credential in Default(). It must
// never authenticate anything in production.
const PlaceholderToken = "dev-token-please-change"

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

	// 1. Client authentication. In platform mode with no identity-svc and no
	// bff-edge, wirePlatform leaves the verifier nil and the core falls back to
	// the static YAML table — i.e. the edge stops asking the control plane who
	// a client is.
	if !c.IsStandaloneMode() && !c.MultiRegion.IsBFFEdge() {
		bad = append(bad, "platform mode without a bff-edge connection: since every edge reaches the control "+
			"plane through bff-edge (F3 step 2b), clients here would be authenticated against the static "+
			"accepted_tokens table instead of identity-svc (set multi_region, or say mode: standalone if "+
			"that is the intent)")
	}

	// 2. The shipped placeholder credential, in ANY mode — a standalone edge
	// carrying it is just as open as a platform one.
	for i, t := range c.AcceptedTokens {
		if strings.TrimSpace(t.Token) == PlaceholderToken {
			bad = append(bad, fmt.Sprintf("accepted_tokens[%d] is still the shipped placeholder %q, "+
				"which is published in the open-source tree: anyone can authenticate as tenant %q", i, PlaceholderToken, t.TenantID))
		}
	}

	// 3. A platform relay that accepts ungranted clients. kind=platform means
	// coord advertises this node in the PLATFORM DERP map, so without grant
	// verification it relays for anyone who finds it — traffic that is neither
	// attributable to an org nor stoppable when one is over quota.
	if c.RunsRelay() && c.Relay.IsPlatformKind() && !c.Relay.RequireAuth {
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
