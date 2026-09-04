package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/calabi/calabi/apps/client/internal/mesh"
	"github.com/calabi/calabi/apps/client/internal/platform/statusapi"
)

// writeCreds points creds.Path() at a temp file (CALABI_CONFIG) and writes the
// given fingerprint into it. Exercises the real resolveFingerprint(), which
// re-reads from DISK on every reconcile — the property this whole test is about.
func writeCreds(t *testing.T, fingerprint string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.json")
	body := map[string]any{}
	if fingerprint != "" {
		body["fingerprint"] = fingerprint
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CALABI_CONFIG", p)
}

// The daemon reports its Publish-side fingerprint to the coordinator only when
// it registers. On a fresh install — a container with no persisted config being
// the common case — the mesh session comes up before the device registration
// that mints it, so the node enrols with "" and the console can't link it to its
// client record. Nothing used to notice for the rest of the boot.
//
// It is a DECLARATION, so it now goes out on the declaration-update RPC: the
// console gets its link and the datapath is never touched.
func TestMeshController_ReportsFingerprintWithoutReEnrolling(t *testing.T) {
	writeCreds(t, "")
	var started []*startRec
	c := newTestController(recordingStarter(&started))
	enr := meshEnrollment{Enabled: true, CoordAddr: "coord:7014", RelayAddr: "derp:3340", OrgID: 7}
	ctx := context.Background()

	c.reconcile(ctx, enr)
	if len(started) != 1 {
		t.Fatalf("initial start count = %d, want 1", len(started))
	}
	// Still nothing registered: a steady poll must not churn the datapath just
	// because the fingerprint is absent.
	c.reconcile(ctx, enr)
	if len(started) != 1 {
		t.Fatalf("poll with no fingerprint restarted: count = %d, want 1", len(started))
	}

	// Device registration completes and persists the fingerprint.
	writeCreds(t, "fp_abc")
	c.reconcile(ctx, enr)

	if len(started) != 1 {
		t.Fatalf("reporting a fingerprint restarted the session: count = %d, want 1", len(started))
	}
	lease := started[0].lease
	if len(lease.updateFPs) != 1 || lease.updateFPs[0] != "fp_abc" {
		t.Fatalf("fingerprint not pushed to the running session: %v", lease.updateFPs)
	}
	if lease.stopped {
		t.Error("session was stopped for a declaration-only change")
	}

	// And it settles: knowing it must not keep re-sending.
	c.reconcile(ctx, enr)
	c.reconcile(ctx, enr)
	if len(lease.updateFPs) != 1 {
		t.Fatalf("fingerprint re-sent on steady polls: %d times", len(lease.updateFPs))
	}
	if len(started) != 1 {
		t.Fatalf("steady polls churned: count = %d, want 1", len(started))
	}
}

// An older coordinator answers Unimplemented (surfaced as mesh.ErrNotEnrolled).
// The edit still has to land, so the fallback is the old behaviour: re-enroll.
func TestMeshController_FingerprintFallsBackToReEnroll(t *testing.T) {
	writeCreds(t, "")
	var started []*startRec
	c := newTestController(recordingStarter(&started))
	enr := meshEnrollment{Enabled: true, CoordAddr: "coord:7014", RelayAddr: "derp:3340", OrgID: 7}
	ctx := context.Background()

	c.reconcile(ctx, enr)
	started[0].lease.updateErr = mesh.ErrNotEnrolled

	writeCreds(t, "fp_abc")
	c.reconcile(ctx, enr)
	if len(started) != 2 {
		t.Fatalf("update failure did not fall back to re-enrolling: count = %d, want 2", len(started))
	}
	if !started[0].lease.stopped {
		t.Error("the fingerprint-less lease was not stopped")
	}
	if started[1].cfg.Coord != "coord:7014" {
		t.Fatalf("re-enrolled with the wrong config: %+v", started[1].cfg)
	}
}

// One direction only. "" is what the daemon reports when it has no registration
// YET *and* when creds momentarily won't load; treating the second as a change
// would push an empty value — or restart — over a transient read failure.
func TestMeshController_LosingTheFingerprintDoesNothing(t *testing.T) {
	writeCreds(t, "fp_abc")
	var started []*startRec
	c := newTestController(recordingStarter(&started))
	enr := meshEnrollment{Enabled: true, CoordAddr: "coord:7014", RelayAddr: "derp:3340", OrgID: 7}
	ctx := context.Background()

	c.reconcile(ctx, enr)
	if len(started) != 1 {
		t.Fatalf("initial start count = %d, want 1", len(started))
	}

	// creds unreadable on this tick.
	t.Setenv("CALABI_CONFIG", filepath.Join(t.TempDir(), "gone.json"))
	c.reconcile(ctx, enr)
	// It comes back — same value, still nothing to do.
	writeCreds(t, "fp_abc")
	c.reconcile(ctx, enr)

	if len(started) != 1 {
		t.Fatalf("a vanishing fingerprint churned the session: count = %d, want 1", len(started))
	}
	if n := len(started[0].lease.updateFPs); n != 0 {
		t.Fatalf("sent %d pointless declaration updates", n)
	}
}

// Editing a service list changes no addresses, so it must not cost the
// datapath. It used to: the only way a declaration reached the coordinator was
// RegisterNode, so the session was torn down and rebuilt — new WireGuard config,
// re-dialled relays, re-punched direct paths, and a home-relay flap.
func TestMeshController_ServiceEditUpdatesInPlace(t *testing.T) {
	writeCreds(t, "fp_abc")
	var started []*startRec
	c := newTestController(recordingStarter(&started))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.ctx = ctx
	c.reconcile(ctx, meshEnrollment{Enabled: true, CoordAddr: "coord:7014", RelayAddr: "derp:3340", OrgID: 7})

	if err := c.SetMeshServices([]statusapi.MeshServiceDecl{
		{Name: "db", Proto: "tcp", Port: 5432},
	}); err != nil {
		t.Fatalf("SetMeshServices: %v", err)
	}

	if len(started) != 1 {
		t.Fatalf("a service edit restarted the session: count = %d, want 1", len(started))
	}
	if started[0].lease.stopped {
		t.Error("session stopped for a service edit")
	}
	got := started[0].lease.updates
	if len(got) != 1 || len(got[0]) != 1 || got[0][0].Name != "db" || got[0][0].Port != 5432 {
		t.Fatalf("declarations not pushed to the running session: %+v", got)
	}
}

// Same fallback as the fingerprint path: if the update can't be delivered, the
// edit still has to reach the coordinator, and re-enrolling is how.
func TestMeshController_ServiceEditFallsBackToReEnroll(t *testing.T) {
	writeCreds(t, "fp_abc")
	var started []*startRec
	c := newTestController(recordingStarter(&started))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.ctx = ctx
	c.reconcile(ctx, meshEnrollment{Enabled: true, CoordAddr: "coord:7014", RelayAddr: "derp:3340", OrgID: 7})
	started[0].lease.updateErr = errors.New("coordinator says no")

	if err := c.SetMeshServices([]statusapi.MeshServiceDecl{
		{Name: "db", Proto: "tcp", Port: 5432},
	}); err != nil {
		t.Fatalf("SetMeshServices: %v", err)
	}
	// Rebind stops the session and re-fetches the enrollment; this harness has no
	// bff to answer, so what's observable here is the teardown — which is exactly
	// the thing the fast path is supposed to avoid and the fallback is supposed
	// to do.
	if !started[0].lease.stopped {
		t.Error("failed update did not fall back to re-enrolling: session still running")
	}
	if c.lease != nil {
		t.Error("lease not cleared, so the next reconcile won't re-enroll")
	}
}
