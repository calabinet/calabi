package main

import (
	"context"
	"io"
	"log/slog"
	"reflect"
	"testing"

	"github.com/calabinet/calabi/apps/client/internal/creds"
	"github.com/calabinet/calabi/apps/client/internal/mesh"
	"github.com/calabinet/calabi/apps/client/internal/platform/meshenroll"
)

// setEdgeAnchor persists the edge affinity and anchor the way the status API's
// switch handlers and the edge picker do, so meshHomePreference / meshHomePin
// read what a real switch leaves behind.
func setEdgeAnchor(t *testing.T, preferPlatform bool, lastEdgeRegion string) {
	t.Helper()
	c, _ := creds.Load()
	if c == nil {
		c = &creds.Config{}
	}
	c.PreferPlatformEdge = preferPlatform
	c.LastEdgeRegion = lastEdgeRegion
	c.EdgeRegion = ""
	if err := creds.Save(c); err != nil {
		t.Fatalf("save creds: %v", err)
	}
}

var rehomeEnrollment = meshenroll.Enrollment{Enabled: true, CoordAddr: "coord:7014", RelayAddr: "derp:3340", OrgID: 4}

// Flipping "which node I use" moves the relay home on the session that is
// already running. It used to stop that session and enroll a new one — every
// peer connection dropped so that the next latency probe would read a different
// preference.
func TestMeshController_AffinityFlipRehomesWithoutRestarting(t *testing.T) {
	isolateCreds(t)
	setEdgeAnchor(t, true, "") // on the platform

	var started []*startRec
	c := newTestController(recordingStarter(&started))
	c.reconcile(context.Background(), rehomeEnrollment)
	if len(started) != 1 || started[0].cfg.HomePreference != "platform" {
		t.Fatalf("first session: %d started, preference %q; want one, on the platform", len(started), started[0].cfg.HomePreference)
	}
	lease := started[0].lease

	// The user switches to their own node. The switch handler clears the anchor.
	setEdgeAnchor(t, false, "")
	c.reconcile(context.Background(), rehomeEnrollment)

	if len(started) != 1 || lease.stopped {
		t.Fatalf("the flip restarted the session (%d started, stopped=%v); it must re-select in place", len(started), lease.stopped)
	}
	if want := []string{"own|"}; !reflect.DeepEqual(lease.homeSelections, want) {
		t.Fatalf("selections handed to the running session = %v, want %v", lease.homeSelections, want)
	}

	// A steady poll with nothing changed must not hand it over again: each one
	// costs a latency probe of every relay.
	c.reconcile(context.Background(), rehomeEnrollment)
	if len(lease.homeSelections) != 1 {
		t.Fatalf("an unchanged poll re-selected again: %v", lease.homeSelections)
	}
}

// What made the relay lag the edge by thirty seconds in the field: the nudge
// fetched the enrollment from the control plane before it would look at a
// setting that lives on this machine, and when that fetch failed it did
// nothing. Here the control plane is unreachable and the nudge still works.
func TestMeshController_NudgeNeedsNoControlPlane(t *testing.T) {
	isolateCreds(t)
	setEdgeAnchor(t, true, "")

	var started []*startRec
	c := newTestController(recordingStarter(&started))
	c.bffURL = "http://127.0.0.1:1" // nothing listens here: any fetch fails
	c.ctx = context.Background()
	c.reconcile(context.Background(), rehomeEnrollment)
	lease := started[0].lease

	setEdgeAnchor(t, false, "")
	c.Nudge()

	if want := []string{"own|"}; !reflect.DeepEqual(lease.homeSelections, want) {
		t.Fatalf("selections after the nudge = %v, want %v — the nudge depended on reaching the control plane", lease.homeSelections, want)
	}
	if len(started) != 1 || lease.stopped {
		t.Fatalf("the nudge restarted the session (%d started, stopped=%v)", len(started), lease.stopped)
	}
}

// The edge's facility is only known once an edge has been picked, a moment after
// the flip. That second nudge pins the relay to the same facility — in place
// again. It used to be a second full restart, thirty seconds later.
func TestMeshController_NudgePinsToTheEdgeFacilityOnceKnown(t *testing.T) {
	isolateCreds(t)
	setEdgeAnchor(t, false, "")

	var started []*startRec
	c := newTestController(recordingStarter(&started))
	c.reconcile(context.Background(), rehomeEnrollment)
	lease := started[0].lease
	if got := started[0].cfg; got.HomePreference != "own" || got.PinnedHomeRegion != "" {
		t.Fatalf("started with %q / pin %q, want own and no pin yet", got.HomePreference, got.PinnedHomeRegion)
	}

	c.Nudge() // nothing moved: nothing to hand over
	if len(lease.homeSelections) != 0 {
		t.Fatalf("a nudge with nothing changed re-selected: %v", lease.homeSelections)
	}

	setEdgeAnchor(t, false, "cn-chengdu") // the edge landed
	c.Nudge()
	if want := []string{"own|self-cn-chengdu"}; !reflect.DeepEqual(lease.homeSelections, want) {
		t.Fatalf("selections = %v, want %v", lease.homeSelections, want)
	}
	if len(started) != 1 || lease.stopped {
		t.Fatalf("pinning restarted the session (%d started, stopped=%v)", len(started), lease.stopped)
	}
}

// A nudge with no session, or with the mesh paused, changes nothing and breaks
// nothing — and the session that starts next still begins with the selection
// that was current when it started.
func TestMeshController_NudgeWithNothingRunning(t *testing.T) {
	isolateCreds(t)
	setEdgeAnchor(t, true, "")

	var started []*startRec
	c := newTestController(recordingStarter(&started))
	c.Nudge() // no session at all: must not panic

	c.reconcile(context.Background(), rehomeEnrollment)
	lease := started[0].lease

	c.paused = true
	setEdgeAnchor(t, false, "cn-chengdu")
	c.Nudge()
	if len(lease.homeSelections) != 0 {
		t.Fatalf("a paused mesh was re-selected: %v", lease.homeSelections)
	}

	// Resumed: the next reconcile starts a session that begins with what the
	// user chose while it was paused.
	c.paused = false
	c.stopLocked("test: resume")
	c.reconcile(context.Background(), rehomeEnrollment)
	if len(started) != 2 {
		t.Fatalf("sessions started = %d, want a second after the pause", len(started))
	}
	if got := started[1].cfg; got.HomePreference != "own" || got.PinnedHomeRegion != "self-cn-chengdu" {
		t.Fatalf("the new session started with %q / pin %q, want what creds held", got.HomePreference, got.PinnedHomeRegion)
	}
}

// The runner's half: a selection set with no session running is remembered for
// the next one, and one set on a running session reaches its controller.
func TestMeshRunnerSetHomeSelection(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := newMeshRunner(logger, meshConfig{HomePreference: "platform"})

	r.SetHomeSelection("own", "self-cn-chengdu") // no session: must not panic
	if r.cfg.HomePreference != "own" || r.cfg.PinnedHomeRegion != "self-cn-chengdu" {
		t.Fatalf("config after a set with no session: %q / %q", r.cfg.HomePreference, r.cfg.PinnedHomeRegion)
	}

	// A session that comes up AFTER the change starts with it: the selection is
	// copied in as the controller is published, whatever it was built with.
	ctrl := &mesh.Controller{Logger: logger}
	r.publishController(ctrl)
	if ctrl.SetHomeSelection("own", "self-cn-chengdu") {
		t.Fatal("a session published after the change did not start with it")
	}

	// And one already running is told.
	r.SetHomeSelection("platform", "")
	if ctrl.SetHomeSelection("platform", "") {
		t.Fatal("the running controller did not have the selection: setting it again counted as a change")
	}
}
