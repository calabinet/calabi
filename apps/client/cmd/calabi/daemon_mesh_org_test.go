package main

import (
	"context"
	"testing"
)

// meshnet == org, so switching org must move this node to a DIFFERENT mesh.
// Everything else in the enrollment is identical across orgs (coord/relay are
// platform-wide, the name is the hostname), which is exactly why this needs its
// own signal: before org_id, the answer looked unchanged and the node stayed on
// the previous org's meshnet.
func TestMeshController_OrgSwitchRestarts(t *testing.T) {
	var started []*startRec
	c := newTestController(recordingStarter(&started))
	base := meshEnrollment{Enabled: true, CoordAddr: "coord:7014", RelayAddr: "derp:3340", OrgID: 7}

	c.reconcile(context.Background(), base)
	if len(started) != 1 {
		t.Fatalf("initial start count = %d, want 1", len(started))
	}
	if got := c.MeshStatus().OrgID; got != 7 {
		t.Fatalf("MeshStatus.OrgID = %d, want 7", got)
	}

	// Same org again: a steady poll must not churn the datapath.
	c.reconcile(context.Background(), base)
	if len(started) != 1 {
		t.Fatalf("same-org poll restarted: count = %d, want 1", len(started))
	}

	switched := base
	switched.OrgID = 9
	c.reconcile(context.Background(), switched)
	if len(started) != 2 {
		t.Fatalf("org switch did not restart: count = %d, want 2", len(started))
	}
	if !started[0].lease.stopped {
		t.Error("previous org's lease was not stopped")
	}
	if got := c.MeshStatus().OrgID; got != 9 {
		t.Fatalf("MeshStatus.OrgID after switch = %d, want 9", got)
	}
}

// A bff that predates org_id reports 0. That means "unknown", NOT "a different
// org" — reading it the other way would restart every daemon's datapath in the
// fleet the moment the control plane is upgraded.
func TestMeshController_MissingOrgIDDoesNotChurn(t *testing.T) {
	var started []*startRec
	c := newTestController(recordingStarter(&started))
	old := meshEnrollment{Enabled: true, CoordAddr: "coord:7014", RelayAddr: "derp:3340"} // OrgID 0

	c.reconcile(context.Background(), old)
	c.reconcile(context.Background(), old)
	if len(started) != 1 {
		t.Fatalf("old-bff polls restarted: count = %d, want 1", len(started))
	}

	// bff upgraded mid-flight and now reports the org: still the same meshnet,
	// so this must not restart either.
	upgraded := old
	upgraded.OrgID = 7
	c.reconcile(context.Background(), upgraded)
	if len(started) != 1 {
		t.Fatalf("bff upgrade churned the datapath: count = %d, want 1", len(started))
	}
	// ...but the org IS adopted, so the comparison isn't blind for the rest of
	// this session. Without this the lease would sit at "unknown" forever and
	// never notice a later switch on its own.
	if got := c.MeshStatus().OrgID; got != 7 {
		t.Fatalf("MeshStatus.OrgID = %d, want 7 (adopted without restarting)", got)
	}

	// And from here on a real switch IS caught by the poll alone.
	switched := upgraded
	switched.OrgID = 9
	c.reconcile(context.Background(), switched)
	if len(started) != 2 {
		t.Fatalf("switch after adoption not caught: count = %d, want 2", len(started))
	}
}

// Rebind is the immediate path for an identity change (login / logout / org
// switch): it drops the session so the next enrollment re-registers with the
// credential that is now on disk, instead of waiting for a reconnect that may
// not come for hours.
func TestMeshController_RebindDropsSession(t *testing.T) {
	var started []*startRec
	c := newTestController(recordingStarter(&started))
	c.reconcile(context.Background(), meshEnrollment{Enabled: true, CoordAddr: "coord:7014", RelayAddr: "derp:3340", OrgID: 7})
	if len(started) != 1 {
		t.Fatalf("start count = %d, want 1", len(started))
	}

	// ctx nil (controller never Run) → Rebind drops the lease without ticking,
	// which is what we assert here; the re-enroll is reconcile's job.
	c.Rebind("org switch")
	if !started[0].lease.stopped {
		t.Error("Rebind did not stop the running lease")
	}
	if c.lease != nil {
		t.Error("Rebind left a lease behind")
	}
	if got := c.MeshStatus().OrgID; got != 0 {
		t.Errorf("MeshStatus.OrgID after Rebind = %d, want 0 (nothing is enrolled)", got)
	}

	// The next enrollment brings it back on the NEW org.
	c.reconcile(context.Background(), meshEnrollment{Enabled: true, CoordAddr: "coord:7014", RelayAddr: "derp:3340", OrgID: 9})
	if len(started) != 2 {
		t.Fatalf("no re-enrollment after Rebind: count = %d, want 2", len(started))
	}
	if got := c.MeshStatus().OrgID; got != 9 {
		t.Fatalf("MeshStatus.OrgID = %d, want 9", got)
	}
}

// A paused node stays paused across a Rebind: an identity change must not
// silently undo an operator's local stop.
func TestMeshController_RebindKeepsPause(t *testing.T) {
	var started []*startRec
	c := newTestController(recordingStarter(&started))
	c.reconcile(context.Background(), meshEnrollment{Enabled: true, CoordAddr: "coord:7014", RelayAddr: "derp:3340", OrgID: 7})
	if err := c.MeshDown(); err != nil {
		t.Fatalf("MeshDown: %v", err)
	}

	c.Rebind("org switch")
	c.reconcile(context.Background(), meshEnrollment{Enabled: true, CoordAddr: "coord:7014", RelayAddr: "derp:3340", OrgID: 9})
	if len(started) != 1 {
		t.Fatalf("paused node re-enrolled: count = %d, want 1", len(started))
	}
	if !c.MeshStatus().Paused {
		t.Error("pause was lost across Rebind")
	}
}
