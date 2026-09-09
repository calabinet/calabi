package mesh

import (
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Whether this host can install the 1:1 subnet-alias rewrite, and how we came to
// know it.
//
// THE BUG THIS FILE EXISTS FOR, from the field 2026-09-09. A machine that was
// demonstrably rewriting — `iptables -t nat -S PREROUTING` showed
// `-d 100.96.0.0/24 -j NETMAP --to 192.168.1.0/24`, and the daemon had logged
// "mesh subnet alias active" three times — told its operator "this machine
// cannot install alias rules". The console was not reading the installed rules.
// It re-derived the answer on every GET /v1/mesh/advertise by shelling out to
// iptables, and that probe had no way to say "I could not find out": every
// failure collapsed into "this host cannot do it", including losing a race for
// the xtables lock against the daemon's OWN rule installation — which is exactly
// what a route change triggers, one refetch away.
//
// So this file keeps apart three things the old bool ran together:
//
//   - a verdict we OBSERVED — the rules went in, or they did not. The best
//     evidence there is, and free: the work was done anyway.
//   - a verdict we PROBED — nothing is installed yet, so we try it on a chain of
//     our own. A guess, but a well-formed one.
//   - not knowing. Which must never be rendered as "no".

// AliasSupport answers "can this host install the alias rewrite".
type AliasSupport int

const (
	// AliasSupportUnknown means we could not find out right now. Callers MUST NOT
	// report it as unsupported: the console's contract is that a missing
	// alias_supported field is "no answer", and no answer draws no warning.
	AliasSupportUnknown AliasSupport = iota
	AliasSupportYes
	AliasSupportNo
)

// aliasSupportNoTTL is how long a "no" is trusted before we look again.
//
// A "yes" is kept for the life of the process — a kernel that has accepted a
// NETMAP rule will accept another. A "no" is often something the operator is in
// the middle of fixing (`apt install iptables`), and requiring a daemon restart
// to clear a cached refusal is precisely the kind of remedy nobody discovers.
const aliasSupportNoTTL = time.Minute

// probeAliasSupport is the platform probe, behind a variable so the verdict
// logic above can be tested without a kernel. Only tests reassign it.
var probeAliasSupport = probeSubnetAlias

var aliasSupportState struct {
	mu      sync.Mutex
	verdict AliasSupport
	reason  string
	at      time.Time
	logged  AliasSupport // last verdict written to the log, so we say it once
}

// SubnetAliasSupport reports whether this host can install the rewrite, together
// with the reason behind the answer.
//
// It prefers what we have already observed (see noteAliasInstall) over probing,
// and probes only when nothing is known. The probe is not free — it shells out
// to iptables three times — and it is also the only one of the two that can be
// wrong.
func SubnetAliasSupport(logger *slog.Logger) (AliasSupport, string) {
	aliasSupportState.mu.Lock()
	defer aliasSupportState.mu.Unlock()
	switch aliasSupportState.verdict {
	case AliasSupportYes:
		return AliasSupportYes, aliasSupportState.reason
	case AliasSupportNo:
		if time.Since(aliasSupportState.at) < aliasSupportNoTTL {
			return AliasSupportNo, aliasSupportState.reason
		}
	}
	v, reason := probeAliasSupport()
	// Unknown is deliberately not recorded. It is the ABSENCE of an answer;
	// storing it would only stop us asking again, and would shadow a real verdict
	// we already hold.
	if v != AliasSupportUnknown {
		aliasSupportState.verdict, aliasSupportState.reason, aliasSupportState.at = v, reason, time.Now()
	}
	logAliasSupportLocked(logger, v, reason)
	return v, reason
}

// noteAliasInstall records what happened when the rewrite was ACTUALLY
// installed. This outranks every probe: the rules either went in or they did
// not, and no amount of re-deriving beats having done it.
//
// A transient failure records NOTHING. Losing the xtables lock says something
// about what else is running, not about what the kernel can do — and writing it
// down as "no" is the field bug one layer further in.
func noteAliasInstall(logger *slog.Logger, err error) {
	v, reason := AliasSupportYes, "the rewrite is installed"
	if err != nil {
		if aliasFailureIsTransient(err.Error()) {
			return
		}
		v, reason = AliasSupportNo, err.Error()
	}
	aliasSupportState.mu.Lock()
	defer aliasSupportState.mu.Unlock()
	aliasSupportState.verdict, aliasSupportState.reason, aliasSupportState.at = v, reason, time.Now()
	logAliasSupportLocked(logger, v, reason)
}

// logAliasSupportLocked says WHY, once per change of verdict.
//
// The old probe returned a bare bool with every error swallowed, so an operator
// staring at "this machine cannot install alias rules" had nothing whatsoever to
// look up — not even which of the four shell-outs failed.
func logAliasSupportLocked(logger *slog.Logger, v AliasSupport, reason string) {
	if logger == nil || v == aliasSupportState.logged {
		return
	}
	aliasSupportState.logged = v
	switch v {
	case AliasSupportYes:
		logger.Info("mesh: this host can install subnet alias rewrites", "why", reason)
	case AliasSupportNo:
		logger.Warn("mesh: this host cannot install subnet alias rewrites; subnets are published under their real "+
			"addresses, so peers whose own LAN collides with them cannot reach them", "why", reason)
	default:
		logger.Info("mesh: could not determine whether this host can install subnet alias rewrites; "+
			"reporting no answer rather than a wrong one", "why", reason)
	}
}

// aliasFailureIsTransient reports whether a failure was iptables being unable to
// RUN, as opposed to the kernel being unable to NETMAP.
//
// The xtables lock is the one that actually bit us. The daemon holds it while it
// reinstalls MASQUERADE and NETMAP rules after a route change — which is the
// same moment the console refetches and probes — so the busier the machine is
// with aliases, the more likely it was to be told it could not have them.
func aliasFailureIsTransient(msg string) bool {
	for _, s := range []string{
		"xtables lock", // iptables' own message, exit code 4
		"Resource temporarily unavailable",
		"signal: killed", // our own ctx timeout reaped it
		"context deadline exceeded",
	} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// aliasProbeVerdict turns one failed step into an answer. The whole point is the
// Unknown branch: a step that could not RUN has told us nothing about xt_NETMAP,
// and saying "no" on its behalf is what put a wrong warning in front of an
// operator whose rules were working.
func aliasProbeVerdict(step string, out []byte, err error) (AliasSupport, string) {
	msg := strings.TrimSpace(string(out))
	if msg == "" {
		msg = err.Error()
	}
	reason := "could not " + step + ": " + msg
	if aliasFailureIsTransient(msg) || aliasFailureIsTransient(err.Error()) {
		return AliasSupportUnknown, reason
	}
	return AliasSupportNo, reason
}
