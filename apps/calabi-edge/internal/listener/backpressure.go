package listener

import "github.com/calabi/calabi/apps/calabi-edge/internal/ratelimit"

// globalAdmit applies the process-wide (org-agnostic) backpressure to a
// freshly-accepted visitor connection (Phase B anti-abuse). It is checked
// at the accept loop — BEFORE the per-org gates in the handler and before
// any sniff/route work — so a flood is shed as early as possible.
//
// Returns (release, "") when the connection may proceed; the caller MUST
// arrange for release to run on teardown (defer in the per-conn goroutine).
// Returns (nil, outcome) when the connection was shed; outcome is the
// metrics label ("global_rate_limited" | "global_conn_capped") and the
// caller closes/drops the connection.
//
// A nil limiter admits everything (release is a no-op), so unconfigured
// edges pay nothing.
func globalAdmit(g *ratelimit.GlobalLimiter) (release func(), shedOutcome string) {
	if !g.AllowAccept() {
		return nil, "global_rate_limited"
	}
	rel, ok := g.AcquireConn()
	if !ok {
		return nil, "global_conn_capped"
	}
	return rel, ""
}
