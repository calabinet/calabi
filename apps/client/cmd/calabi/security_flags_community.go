package main

// This build supports IP allow/deny + HTTP Basic auth (security_flags.go). It
// does not support the advanced per-tunnel knobs (connection rate limiting,
// request-header rewrite, OAuth login wall): registerAdvancedFlags wires no
// flags for them, and applyAdvanced strips any such block — whether from
// --security-file or tunnels.yaml — and warns.

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

// registerAdvancedFlags wires no flags — this build has no advanced knobs.
func (sf *securityFlags) registerAdvancedFlags(*flag.FlagSet, *[]string) {}

// applyAdvanced strips the advanced blocks (rate limit / header rewrite /
// OAuth) from the security config and warns if any were present (from
// --security-file or tunnels.yaml).
func (sf *securityFlags) applyAdvanced(sec *secBlock) error {
	stripped := sec.RateLimit != nil || sec.RequestHeaders != nil || sec.OAuth != nil
	sec.RateLimit, sec.RequestHeaders, sec.OAuth = nil, nil, nil
	fromFields := sf.rate != 0 || len(sf.setHeader) > 0 || len(sf.delHeader) > 0 ||
		strings.TrimSpace(sf.oauthProvider) != ""
	if stripped || fromFields {
		fmt.Fprintln(os.Stderr,
			"note: rate limiting, request-header rewrite, and the OAuth login wall are "+
				"not supported by this build — those entries were ignored. "+
				"IP allow/deny and Basic auth still apply.")
	}
	return nil
}
