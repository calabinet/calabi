package mesh

import (
	"errors"
	"testing"
	"time"
)

func resetAliasSupport(t *testing.T) {
	t.Helper()
	prev := probeAliasSupport
	clear := func() {
		aliasSupportState.mu.Lock()
		defer aliasSupportState.mu.Unlock()
		aliasSupportState.verdict, aliasSupportState.reason = AliasSupportUnknown, ""
		aliasSupportState.at, aliasSupportState.logged = time.Time{}, AliasSupportUnknown
	}
	t.Cleanup(func() { probeAliasSupport = prev; clear() })
	clear()
}

// THE BUG THIS FILE EXISTS FOR, from the field 2026-09-09.
//
// The machine was rewriting. `iptables -t nat -S PREROUTING` showed
//
//	-A PREROUTING -d 100.96.0.0/24 -j NETMAP --to 192.168.1.0/24
//
// and the daemon had logged "mesh subnet alias active" three times. The console
// still told its operator the machine could not install alias rules, because the
// answer was re-derived by a probe that ran head-on into the iptables work the
// daemon itself was doing, and read the lost race as a missing kernel feature.
//
// Having installed the rules is the strongest evidence there is. No probe may
// overrule it.
func TestAnInstalledRewriteBeatsAProbeThatSaysOtherwise(t *testing.T) {
	resetAliasSupport(t)
	probeAliasSupport = func() (AliasSupport, string) {
		t.Error("probed even though the rules are known to be installed")
		return AliasSupportNo, "xt_NETMAP missing"
	}
	noteAliasInstall(nil, nil) // what the controller reports on a successful install

	if got, _ := SubnetAliasSupport(nil); got != AliasSupportYes {
		t.Fatalf("SubnetAliasSupport = %v after a successful install, want AliasSupportYes", got)
	}
}

// The other half of the same bug, one layer in: losing the xtables lock is a
// statement about what else is running, not about what the kernel can do.
// Recording it would re-create the field failure through the install path
// instead of the probe path.
func TestLosingTheXtablesLockNeverBecomesUnsupported(t *testing.T) {
	resetAliasSupport(t)
	probeAliasSupport = func() (AliasSupport, string) { return AliasSupportYes, "probe says yes" }
	noteAliasInstall(nil, nil)

	lock := errors.New("iptables alias rewrite [...]: exit status 4: " +
		"Another app is currently holding the xtables lock. Perhaps you want to use the -w option?")
	noteAliasInstall(nil, lock)

	if got, _ := SubnetAliasSupport(nil); got != AliasSupportYes {
		t.Fatalf("a contended lock downgraded a working host to %v", got)
	}
}

// A genuine refusal must still be recorded, or the warning this whole surface
// exists for would never appear.
func TestAGenuineRefusalIsRecorded(t *testing.T) {
	resetAliasSupport(t)
	probeAliasSupport = func() (AliasSupport, string) {
		t.Error("probed even though an install already answered the question")
		return AliasSupportYes, ""
	}
	noteAliasInstall(nil, errors.New("iptables: No chain/target/match by that name "+
		"(the NETMAP target needs the xt_NETMAP module)"))

	got, why := SubnetAliasSupport(nil)
	if got != AliasSupportNo {
		t.Fatalf("SubnetAliasSupport = %v after a real refusal, want AliasSupportNo", got)
	}
	if why == "" {
		t.Error("no reason recorded; an operator reading the warning has nothing to look up")
	}
}

// Unknown is the absence of an answer. Caching it would stop us asking again.
func TestUnknownIsNotCached(t *testing.T) {
	resetAliasSupport(t)
	calls := 0
	probeAliasSupport = func() (AliasSupport, string) {
		calls++
		if calls < 3 {
			return AliasSupportUnknown, "could not install a NETMAP rule: xtables lock"
		}
		return AliasSupportYes, "installed cleanly"
	}
	for i := 1; i <= 2; i++ {
		if got, _ := SubnetAliasSupport(nil); got != AliasSupportUnknown {
			t.Fatalf("call %d = %v, want AliasSupportUnknown", i, got)
		}
	}
	if got, _ := SubnetAliasSupport(nil); got != AliasSupportYes {
		t.Fatalf("the third call = %v, want AliasSupportYes — an unknown was cached and stopped the retry", got)
	}
	if calls != 3 {
		t.Errorf("probed %d times, want 3", calls)
	}
}

// A yes is kept for the life of the process: a kernel that has run a NETMAP rule
// will run another, and re-probing costs three shell-outs on every console poll.
func TestAYesIsNotReprobed(t *testing.T) {
	resetAliasSupport(t)
	calls := 0
	probeAliasSupport = func() (AliasSupport, string) { calls++; return AliasSupportYes, "ok" }
	for range 5 {
		SubnetAliasSupport(nil)
	}
	if calls != 1 {
		t.Errorf("probed %d times for a cached yes, want 1", calls)
	}
}

// A no expires, because it is usually something the operator is in the middle of
// fixing. Requiring a daemon restart to clear it is a remedy nobody discovers.
func TestANoIsRetriedSoInstallingIptablesTakesEffect(t *testing.T) {
	resetAliasSupport(t)
	probeAliasSupport = func() (AliasSupport, string) { return AliasSupportNo, "no NETMAP target" }
	if got, _ := SubnetAliasSupport(nil); got != AliasSupportNo {
		t.Fatalf("first probe = %v, want AliasSupportNo", got)
	}
	probeAliasSupport = func() (AliasSupport, string) { return AliasSupportYes, "operator installed iptables" }
	if got, _ := SubnetAliasSupport(nil); got != AliasSupportNo {
		t.Fatalf("a fresh no was re-probed immediately (= %v); that is three shell-outs per poll", got)
	}

	aliasSupportState.mu.Lock()
	aliasSupportState.at = time.Now().Add(-aliasSupportNoTTL - time.Second)
	aliasSupportState.mu.Unlock()

	if got, _ := SubnetAliasSupport(nil); got != AliasSupportYes {
		t.Fatalf("after %v the no was still cached (= %v); the fix needs a daemon restart to be noticed",
			aliasSupportNoTTL, got)
	}
}

func TestAliasFailureIsTransient(t *testing.T) {
	for _, tc := range []struct {
		name string
		msg  string
		want bool
	}{
		{"the one that bit us", "exit status 4: Another app is currently holding the xtables lock.", true},
		{"our own timeout reaped it", "signal: killed", true},
		{"the context gave up first", "context deadline exceeded", true},
		{"kernel has no such target", "iptables: No chain/target/match by that name.", false},
		{"not running as root", "iptables v1.8.8 (nf_tables): Permission denied (you must be root)", false},
		{"no backend at all", "neither iptables nor nft was found", false},
		{"nothing", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := aliasFailureIsTransient(tc.msg); got != tc.want {
				t.Fatalf("aliasFailureIsTransient(%q) = %v, want %v", tc.msg, got, tc.want)
			}
		})
	}
}

// aliasProbeVerdict is where a failed step becomes an answer, and the Unknown
// branch is the whole point of the change: a step that could not RUN has said
// nothing about xt_NETMAP.
func TestAliasProbeVerdict(t *testing.T) {
	for _, tc := range []struct {
		name string
		out  string
		err  error
		want AliasSupport
	}{
		{"lock contention", "Another app is currently holding the xtables lock.", errors.New("exit status 4"), AliasSupportUnknown},
		{"missing target", "iptables: No chain/target/match by that name.", errors.New("exit status 1"), AliasSupportNo},
		{"silent failure falls back to the error", "", errors.New("executable file not found in PATH"), AliasSupportNo},
		{"timeout carried on the error, not the output", "", errors.New("signal: killed"), AliasSupportUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := aliasProbeVerdict("install a NETMAP rule", []byte(tc.out), tc.err)
			if got != tc.want {
				t.Fatalf("aliasProbeVerdict = %v, want %v", got, tc.want)
			}
			if reason == "" {
				t.Error("empty reason: the bare-bool version left operators with nothing to look up")
			}
		})
	}
}
