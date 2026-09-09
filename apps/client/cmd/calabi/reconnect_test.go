package main

import (
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

// netErr is what a failure to establish a session looks like when the machine
// itself has no network: nothing reached the control plane, so nothing came back
// to classify.
var netErr = fmt.Errorf("dial edge: %w", &net.OpError{Op: "dial", Err: errors.New("no route to host")})

// THE BUG THIS FILE EXISTS FOR, as the user hit it.
//
// The reconnect loop used to stop after 10 consecutive failures and wait for a
// human to click something. A home connection that dropped for three minutes
// therefore killed the tunnel plane permanently — while the mesh plane, which
// has no cap at all, came back on its own the moment the link returned. The user
// saw exactly that: "网络恢复后，发现组网功能正常，但隧道功能不正常".
//
// No number of network failures may ever produce "stop".
func TestANetworkOutageNeverStopsTheRetryLoop(t *testing.T) {
	for _, fails := range []int{1, 9, 10, 11, 100, 10_000} {
		wait, needsOperator := reconnectDelay(netErr, fails)
		if wait <= 0 {
			t.Errorf("after %d network failures the delay is %v; a non-positive wait is how a loop stops", fails, wait)
		}
		if needsOperator {
			t.Errorf("after %d network failures the daemon asked for an operator; nobody can fix a down link from the SPA", fails)
		}
	}
}

// The back-off must stay bounded, because this cap IS the worst case for how
// long a machine keeps carrying nothing after its network comes back. An
// unbounded doubling would trade a problem nobody has (too many failed dials
// into a dead link) for the one this whole change is about.
func TestTheBackoffIsBoundedSoRecoveryIsBounded(t *testing.T) {
	for _, fails := range []int{1, 2, 3, 5, 20, 5_000} {
		wait, _ := reconnectDelay(netErr, fails)
		if wait > maxRetryDelay {
			t.Errorf("after %d failures the wait is %v, past the %v cap", fails, wait, maxRetryDelay)
		}
	}
	if got, want := networkBackoff(1), baseRetryDelay; got != want {
		t.Errorf("first retry waits %v, want %v", got, want)
	}
	// And it does grow — a fixed cadence would re-resolve DNS every 15s for a
	// laptop that is off the network for a day.
	if networkBackoff(3) <= networkBackoff(1) {
		t.Errorf("the delay does not grow: %v then %v", networkBackoff(1), networkBackoff(3))
	}
}

// The cap did one thing right, and it must survive: when the control plane
// answers "there is no edge in the region you are anchored to", cross-region
// auto-switch is off, so the daemon genuinely cannot fix it and the user must
// pick another region. Deleting the cap outright would have deleted the only
// prompt that tells them so.
func TestTheRegionAnswerStillRaisesTheManualSwitchPrompt(t *testing.T) {
	err := errRegionHasNoEdge("cn-chengdu")
	if _, needsOperator := reconnectDelay(err, operatorHintAfter); !needsOperator {
		t.Fatalf("after %d definitive 'no edge here' answers the prompt was not raised", operatorHintAfter)
	}
	// But not on the first one: an edge rolling restart empties a region for a
	// few seconds, and alarming the user through that is worse than waiting.
	if _, needsOperator := reconnectDelay(err, 1); needsOperator {
		t.Error("a single 'no edge here' answer raised the prompt; that is one rolling restart away from crying wolf")
	}
}

// THE ACTUAL BEHAVIOUR CHANGE. Raising the prompt and giving up used to be one
// action; they are now two, and only the first survives.
//
// The region case heals itself as well — the region's edge comes back — so a
// daemon that stopped dialling stayed down long after the cause was gone. On a
// machine installed as a service that is terminal: no SPA is open, nothing ever
// nudges reloadCh, and the only cure is a service restart nobody knows to do.
func TestThePromptDoesNotMeanTheDaemonStoppedTrying(t *testing.T) {
	for _, fails := range []int{operatorHintAfter, operatorHintAfter + 50, 10_000} {
		wait, needsOperator := reconnectDelay(errRegionHasNoEdge("cn-chengdu"), fails)
		if !needsOperator {
			t.Fatalf("prompt dropped at %d failures", fails)
		}
		if wait <= 0 {
			t.Errorf("with the prompt up, the wait is %v — the daemon stopped retrying behind it", wait)
		}
		// Slow, though: the answer is definitive, so re-asking every 15s is noise
		// in the log and load on a control plane that already said no.
		if wait < baseRetryDelay {
			t.Errorf("parked retry cadence %v is faster than the ordinary one (%v)", wait, baseRetryDelay)
		}
	}
}

// The classification has to survive the wrapping the call sites do, because
// errors.Is through %w is the only thing standing between "tell the user to
// switch region" and "retry silently forever".
func TestTheClassificationSurvivesWrapping(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"region has no edge", errRegionHasNoEdge("us-west"), true},
		// This row said `true` and that is how the bug shipped: the test pinned
		// what the code did instead of what was required. Unreachable is a
		// NETWORK failure and must never ask for an operator.
		{"discovery failed because the control plane was unreachable", errEdgeDiscoveryFailed("bff-console unreachable and no default"), false},
		{"wrapped again by a caller", fmt.Errorf("session: %w", errRegionHasNoEdge("eu-central")), true},
		{"a dead link", netErr, false},
		{"a plain string that merely mentions a region", errors.New("no healthy edge in region \"us-west\""), false},
		{"nothing at all", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := errors.Is(tc.err, errOperatorMustSwitchRegion); got != tc.want {
				t.Fatalf("errors.Is(%v, errOperatorMustSwitchRegion) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// A user reading the log while their tunnels are down needs the region named:
// the remedy is "switch to a different one", which is not actionable without
// knowing which one they are stuck on.
func TestTheRegionErrorNamesTheRegion(t *testing.T) {
	if got := errRegionHasNoEdge("cn-chengdu").Error(); !contains(got, "cn-chengdu") {
		t.Errorf("error %q does not name the region the user has to switch away from", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// Guard the arithmetic that the two constants imply, so a later edit to either
// one has to face what it costs: this is the ceiling on how long a machine keeps
// carrying nothing after its link returns.
func TestWorstCaseRecoveryLagStaysUnderAMinute(t *testing.T) {
	if maxRetryDelay > time.Minute {
		t.Errorf("maxRetryDelay is %v: a machine can stay dark that long after its network is back", maxRetryDelay)
	}
}

// THE FIELD REGRESSION, timed to the second from the user's log 2026-09-09.
//
//	17:19:33  session ended; reconnecting
//	17:19:51  connect failed; retrying  fails=1  next_try_in=15s
//	17:20:09  connect failed; retrying  fails=2  next_try_in=15s
//	17:20:27  no healthy edge in the anchored region ... fails=3  next_try_in=5m0s
//	17:25:28  edge selected            <- 17:20:27.975 + 5m00 = 17:25:27.975
//
// The failure underneath every one of those was
//
//	edgepicker: GET /v1/edges failed ... err="context deadline exceeded"
//
// i.e. the control plane was UNREACHABLE because the machine had no network —
// edgepicker's tier-4 fall-through, which sets NoUsableEdge. Routing that into
// the operator class made a plain outage cost five minutes of downtime after the
// link was already back, while the mesh recovered in seconds.
//
// Reaching bff-console is what distinguishes the two, and only the daemon's
// RegionUnavailable path implies it.
func TestAnUnreachableControlPlaneIsNetworkFailureNotAnOperatorProblem(t *testing.T) {
	// The exact error the field build produced.
	err := errEdgeDiscoveryFailed("edge discovery failed and the only fallback is the dev default (); " +
		"not dialling it — set CALABI_SERVER to pin an edge, or fix reachability to https://api.calabi.net")

	for _, fails := range []int{1, 3, 4, 10, 100} {
		wait, needsOperator := reconnectDelay(err, fails)
		if needsOperator {
			t.Errorf("after %d unreachable-control-plane failures the daemon asked for an operator; "+
				"switching region cannot fix a link that reaches nothing", fails)
		}
		if wait > maxRetryDelay {
			t.Errorf("after %d failures the wait is %v, past the %v network cap — an outage would "+
				"again outlast the network it was caused by", fails, wait, maxRetryDelay)
		}
	}
	// Specifically: it must not land on the parked cadence that caused this.
	if wait, _ := reconnectDelay(err, operatorHintAfter); wait >= parkedRetryInterval {
		t.Errorf("waits %v at the operator threshold — this is the 5-minute park that shipped", wait)
	}
}
