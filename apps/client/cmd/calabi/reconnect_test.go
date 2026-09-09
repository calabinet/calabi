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
		{"discovery failed with nothing to fall back to", errEdgeDiscoveryFailed("bff-console unreachable and no default"), true},
		{"wrapped again by a caller", fmt.Errorf("session: %w", errRegionHasNoEdge("eu-central")), true},
		{"a dead link", netErr, false},
		{"a plain string that merely mentions a region", errors.New("no healthy edge in region \"us-west\""), false},
		{"nothing at all", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := errors.Is(tc.err, errNoUsableEdge); got != tc.want {
				t.Fatalf("errors.Is(%v, errNoUsableEdge) = %v, want %v", tc.err, got, tc.want)
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
