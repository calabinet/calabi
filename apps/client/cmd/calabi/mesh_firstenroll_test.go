package main

import (
	"context"
	"testing"
)

// A fingerprint present at the FIRST enrollment rides that registration; there
// is no session to update and nothing has "arrived since we enrolled". The log
// used to say a re-registration had happened, which is a lie to read while
// chasing a missing client link — and it was the exact line that showed up in
// production when the enrollment was in fact the first one.
func TestMeshController_FirstEnrollmentIsNotAFingerprintArrival(t *testing.T) {
	writeCreds(t, "fp_abc")
	var started []*startRec
	c := newTestController(recordingStarter(&started))
	enr := meshEnrollment{Enabled: true, CoordAddr: "coord:7014", RelayAddr: "derp:3340", OrgID: 7}
	ctx := context.Background()

	c.reconcile(ctx, enr)
	if len(started) != 1 {
		t.Fatalf("start count = %d, want 1", len(started))
	}
	// It went out with the registration, so nothing was pushed separately...
	if n := len(started[0].lease.updateFPs); n != 0 {
		t.Fatalf("pushed %d declaration updates during a first enrollment", n)
	}
	// ...and it is remembered, so the next tick doesn't treat it as new.
	if c.deviceFP != "fp_abc" {
		t.Fatalf("deviceFP = %q, want it recorded from the enrollment", c.deviceFP)
	}
	c.reconcile(ctx, enr)
	if len(started) != 1 {
		t.Fatalf("second tick re-enrolled: count = %d, want 1", len(started))
	}
}
