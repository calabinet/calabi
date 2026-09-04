package main

import (
	"fmt"
	"os"
	"strings"
)

// prodguard.go — refuse to run a PRODUCTION coordinator in a degraded posture.
//
// Why (full-oss-plan F0.2): coord is full of operator-friendly fallbacks — no
// identity address means "dev static auth", no quota address means "unlimited",
// an explicit flag means "serve the admin API unauthenticated". Each is correct
// for a laptop and catastrophic in production, and every one of them announces
// itself with a log line nobody reads.
//
// Once the source is public, those fallbacks are also a published playbook: an
// attacker who can make a dependency unreachable at boot gets a coordinator
// that authenticates every node with a well-known dev key. So in production the
// degradations stop being degradations and become startup failures.
//
// The signal is CALABI_ENV=production, set in docker-compose.yml itself rather
// than in.env — a deployment is production BY CONSTRUCTION, not because an
// operator remembered to add a line.

// isProduction reports whether this process claims a production deployment.
func isProduction() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("CALABI_ENV"))) {
	case "production", "prod":
		return true
	}
	return false
}

// checkProductionPosture returns an error naming EVERY active fail-open
// degradation (not just the first — an operator fixing a boot failure should
// see the whole list, not play whack-a-mole across restarts). Returns nil when
// CALABI_ENV is not production.
func checkProductionPosture() error {
	if !isProduction() {
		return nil
	}
	var bad []string

	// Node authentication. There must be a REAL source of it — but "real" is not
	// the same as "ours". Two postures are legitimate:
	//
	//   - platform: CALABI_COORD_IDENTITY_ADDR, verifying tk_ keys through the
	//     IdentityHooks contract;
	//   - self-hosted: CALABI_COORD_AUTHKEYS_FILE, the operator's own key -> meshnet
	//     map (see authstub.go — this is the self-hosted coordinator's real
	//     shape, multi-key with ACL tags, not a dev shim).
	//
	// What is never acceptable in production is the zero-config fallback: a
	// single built-in key ("dev-meshnet-1-key") that maps any caller into
	// meshnet 1. That is the only case this refuses.
	//
	// This distinction matters now that coord ships to self-hosters: an earlier
	// version of this check demanded identity-svc outright, which would have
	// told anyone running their own coordinator that their perfectly correct
	// deployment was misconfigured.
	if !envIsSet("IDENTITY_ADDR") && !envIsSet("AUTHKEYS_FILE") {
		bad = append(bad, "no authentication source: set CALABI_COORD_IDENTITY_ADDR (verify tk_ keys through "+
			"the platform's IdentityHooks) or CALABI_COORD_AUTHKEYS_FILE (your own key -> meshnet map). "+
			"Without either, coord falls back to a single BUILT-IN key that admits any caller into meshnet 1")
	}

	// Mesh-admin surface. F0.1 already refuses a tokenless surface; production
	// additionally refuses the escape hatch itself.
	if envIsTrue("MESH_ADMIN_ALLOW_NOAUTH") {
		bad = append(bad, "CALABI_COORD_MESH_ADMIN_ALLOW_NOAUTH is set: the mesh-admin API would serve every "+
			"meshnet's nodes and ACLs with no credential check (that switch is for local dev only)")
	}

	// Seat cap. Silently unlimited is a billing hole that surfaces only as a
	// revenue gap months later, so make the operator state the intent.
	if envAlias("QUOTA_ADDR", "QUOTA_SVC_ADDR") == "" && !envIsSet("NODE_QUOTA") {
		bad = append(bad, "neither CALABI_COORD_QUOTA_ADDR nor CALABI_COORD_NODE_QUOTA is set: every meshnet "+
			"would get UNLIMITED nodes regardless of plan (set CALABI_COORD_QUOTA_ADDR for per-plan caps, or "+
			"CALABI_COORD_NODE_QUOTA=<n> to state a static cap on purpose)")
	}

	if len(bad) == 0 {
		return nil
	}
	return fmt.Errorf("CALABI_ENV=production but %d fail-open fallback(s) would be active:\n  - %s",
		len(bad), strings.Join(bad, "\n  - "))
}
