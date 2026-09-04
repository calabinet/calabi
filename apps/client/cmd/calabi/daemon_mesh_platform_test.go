package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/calabi/calabi/apps/client/internal/creds"
	"github.com/calabi/calabi/apps/client/internal/mesh"
	"github.com/calabi/calabi/apps/client/internal/platform/statusapi"
)

// fakeLease is a meshLease that records stop() / updateDeclarations() and
// returns a fixed status.
type fakeLease struct {
	st      statusapi.MeshStatus
	obs     []mesh.ServiceObservation
	stopped bool
	// updates records each accepted declaration update; updateErr makes them
	// fail, which is how the re-enroll fallback gets exercised.
	updates   [][]mesh.DeclaredService
	updateFPs []string
	updateErr error
}

func (f *fakeLease) status() statusapi.MeshStatus            { return f.st }
func (f *fakeLease) observations() []mesh.ServiceObservation { return f.obs }
func (f *fakeLease) stop()                                   { f.stopped = true }

func (f *fakeLease) updateDeclarations(_ context.Context, svcs []mesh.DeclaredService, fp string) error {
	if f.updateErr != nil {
		return f.updateErr
	}
	f.updates = append(f.updates, svcs)
	f.updateFPs = append(f.updateFPs, fp)
	return nil
}

type startRec struct {
	cfg   meshConfig
	lease *fakeLease
}

// recordingStarter is a test meshLeaseStarter that records each start's config and
// returns a fakeLease (no tun device involved).
func recordingStarter(started *[]*startRec) meshLeaseStarter {
	return func(_ context.Context, cfg meshConfig, _ func() string) meshLease {
		l := &fakeLease{st: statusapi.MeshStatus{Enabled: true, Up: true, Coord: cfg.Coord, Relay: cfg.Relay, Name: cfg.Name}}
		*started = append(*started, &startRec{cfg: cfg, lease: l})
		return l
	}
}

func newTestController(start meshLeaseStarter) *platformMeshController {
	return &platformMeshController{
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		name:    "node-x",
		authKey: func() string { return "tk_test" },
		start:   start,
		hc:      http.DefaultClient,
		poll:    time.Hour,
	}
}

// A newly-enabled enrollment starts exactly one session with the enrolled
// coordinator/relay and the default node name, and MeshStatus reflects it.
func TestMeshController_EnabledStarts(t *testing.T) {
	var started []*startRec
	c := newTestController(recordingStarter(&started))
	c.reconcile(context.Background(), meshEnrollment{Enabled: true, CoordAddr: "coord:7014", RelayAddr: "derp:3340"})

	if len(started) != 1 {
		t.Fatalf("start count: got %d, want 1", len(started))
	}
	if started[0].cfg.Coord != "coord:7014" || started[0].cfg.Relay != "derp:3340" || started[0].cfg.Name != "node-x" {
		t.Fatalf("started with %+v", started[0].cfg)
	}
	if st := c.MeshStatus(); !st.Enabled || !st.Up || st.Coord != "coord:7014" {
		t.Fatalf("MeshStatus: %+v", st)
	}
}

// The subnet-router / exit-node advertisement (from daemon flags) flows into the
// mesh session config so an auto-enrolled node can be a router / exit node.
func TestMeshController_AdvertiseFlowsThrough(t *testing.T) {
	var started []*startRec
	c := newTestController(recordingStarter(&started))
	c.adv = meshAdvertise{Routes: []string{"192.168.1.0/24"}, ExitNode: true, ExitPeer: "gw"}
	c.reconcile(context.Background(), meshEnrollment{Enabled: true, CoordAddr: "c:1", RelayAddr: "r:1"})
	if len(started) != 1 {
		t.Fatalf("expected 1 start, got %d", len(started))
	}
	got := started[0].cfg
	if len(got.AdvertiseRoutes) != 1 || got.AdvertiseRoutes[0] != "192.168.1.0/24" ||
		!got.AdvertiseExitNode || got.ExitNode != "gw" {
		t.Fatalf("advertise config not threaded: %+v", got)
	}
}

// A node_name in the enrollment overrides the daemon's default name.
func TestMeshController_NodeNameOverride(t *testing.T) {
	var started []*startRec
	c := newTestController(recordingStarter(&started))
	c.reconcile(context.Background(), meshEnrollment{Enabled: true, CoordAddr: "c:1", RelayAddr: "r:1", NodeName: "custom"})
	if started[0].cfg.Name != "custom" {
		t.Fatalf("node name: got %q, want custom", started[0].cfg.Name)
	}
}

// Disabling after enabled tears the session down; status goes back to disabled.
func TestMeshController_DisableStops(t *testing.T) {
	var started []*startRec
	c := newTestController(recordingStarter(&started))
	c.reconcile(context.Background(), meshEnrollment{Enabled: true, CoordAddr: "c:1", RelayAddr: "r:1"})
	c.reconcile(context.Background(), meshEnrollment{Enabled: false})

	if !started[0].lease.stopped {
		t.Fatalf("lease not stopped on disable")
	}
	if st := c.MeshStatus(); st.Enabled {
		t.Fatalf("MeshStatus should be disabled, got %+v", st)
	}
}

// A steady enrollment (same coord/relay) must NOT churn the datapath.
func TestMeshController_SteadyNoRestart(t *testing.T) {
	var started []*startRec
	c := newTestController(recordingStarter(&started))
	enr := meshEnrollment{Enabled: true, CoordAddr: "c:1", RelayAddr: "r:1"}
	c.reconcile(context.Background(), enr)
	c.reconcile(context.Background(), enr)
	c.reconcile(context.Background(), enr)
	if len(started) != 1 {
		t.Fatalf("steady reconcile restarted the session: %d starts", len(started))
	}
}

// A changed coordinator address restarts the session (stop old, start new).
func TestMeshController_AddrChangeRestarts(t *testing.T) {
	var started []*startRec
	c := newTestController(recordingStarter(&started))
	c.reconcile(context.Background(), meshEnrollment{Enabled: true, CoordAddr: "c:1", RelayAddr: "r:1"})
	c.reconcile(context.Background(), meshEnrollment{Enabled: true, CoordAddr: "c:2", RelayAddr: "r:1"})
	if len(started) != 2 {
		t.Fatalf("addr change start count: got %d, want 2", len(started))
	}
	if !started[0].lease.stopped {
		t.Fatalf("old lease not stopped on addr change")
	}
}

// A local `mesh down` pauses participation: it stops the session and no later
// enrollment poll restarts it (until the daemon restarts).
func TestMeshController_MeshDownPauses(t *testing.T) {
	var started []*startRec
	c := newTestController(recordingStarter(&started))
	c.reconcile(context.Background(), meshEnrollment{Enabled: true, CoordAddr: "c:1", RelayAddr: "r:1"})
	if err := c.MeshDown(); err != nil {
		t.Fatal(err)
	}
	if !started[0].lease.stopped {
		t.Fatalf("MeshDown did not stop the session")
	}
	// A subsequent enabled poll must stay paused.
	c.reconcile(context.Background(), meshEnrollment{Enabled: true, CoordAddr: "c:1", RelayAddr: "r:1"})
	if len(started) != 1 {
		t.Fatalf("paused controller restarted: %d starts", len(started))
	}
}

// MeshUp resumes after a MeshDown: it clears the pause and re-enrolls right away
// (fetch + reconcile), bringing the session back without waiting for a poll.
func TestMeshController_MeshUpResumes(t *testing.T) {
	bff := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/mesh/enrollment" {
			_, _ = w.Write([]byte(`{"enabled":true,"coord_addr":"coord:7014","relay_addr":"derp:3340"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer bff.Close()

	var started []*startRec
	c := newTestController(recordingStarter(&started))
	c.bffURL = bff.URL
	c.hc = bff.Client()
	c.ctx = context.Background()

	c.tick(context.Background()) // initial enroll
	if len(started) != 1 {
		t.Fatalf("initial enroll: %d starts", len(started))
	}
	if err := c.MeshDown(); err != nil {
		t.Fatal(err)
	}
	if st := c.MeshStatus(); st.Enabled || !st.Paused {
		t.Fatalf("after down: want paused/!enabled, got %+v", st)
	}
	if err := c.MeshUp(); err != nil {
		t.Fatal(err)
	}
	if len(started) != 2 {
		t.Fatalf("MeshUp did not re-enroll: %d starts", len(started))
	}
	if st := c.MeshStatus(); !st.Enabled || st.Paused {
		t.Fatalf("after up: want enabled/!paused, got %+v", st)
	}
}

// fetch parses a well-formed enrollment and sends the bearer.
func TestMeshController_Fetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/mesh/enrollment" || r.Header.Get("Authorization") != "Bearer tk_test" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"enabled":true,"coord_addr":"coord:7014","relay_addr":"derp:3340"}`))
	}))
	defer srv.Close()

	c := newTestController(nil)
	c.bffURL = srv.URL
	c.hc = srv.Client()
	enr, err := c.fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !enr.wantsRun() || enr.CoordAddr != "coord:7014" || enr.RelayAddr != "derp:3340" {
		t.Fatalf("fetched %+v", enr)
	}
}

// A missing credential (pre-login) yields an error so tick keeps the prior state
// instead of tearing a live meshnet down.
func TestMeshController_FetchNoCredential(t *testing.T) {
	c := newTestController(nil)
	c.bffURL = "http://127.0.0.1:0"
	c.authKey = func() string { return "" }
	if _, err := c.fetch(context.Background()); err == nil {
		t.Fatalf("expected error with no credential")
	}
}

// A non-200 enrollment response is an error (keeps current state).
func TestMeshController_FetchNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	c := newTestController(nil)
	c.bffURL = srv.URL
	c.hc = srv.Client()
	if _, err := c.fetch(context.Background()); err == nil {
		t.Fatalf("expected error on non-200")
	}
}

// End-to-end (daemon side, no tun): a live enrollment fetch drives the REAL
// controller, and the REAL statusapi.Server serves the node's status on /v1/mesh
// — the exact chain the platform daemon's :7400 console takes. A local `mesh
// down` flips the endpoint back to 404 ("unavailable"). The tun datapath is
// unchanged by this slice;
// here the lease starter is faked so no tun/privileges are needed.
func TestMeshController_ServesStatusapiEndToEnd(t *testing.T) {
	bff := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/mesh/enrollment" && r.Header.Get("Authorization") == "Bearer tk_test" {
			_, _ = w.Write([]byte(`{"enabled":true,"coord_addr":"coord:7014","relay_addr":"derp:3340"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer bff.Close()

	var started []*startRec
	c := newTestController(recordingStarter(&started))
	c.bffURL = bff.URL
	c.hc = bff.Client()

	// One enrollment poll → the controller brings the node onto the meshnet.
	c.tick(context.Background())
	if len(started) != 1 {
		t.Fatalf("expected a mesh session after enrollment, got %d", len(started))
	}

	// statusapi serves /v1/mesh from the controller (interface satisfaction +
	// JSON end-to-end).
	s := statusapi.New(nil, statusapi.Config{BFFConsoleURL: "http://127.0.0.1:0", Mesh: c})
	mux := http.NewServeMux()
	s.Register(mux)

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/v1/mesh", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("/v1/mesh = %d, want 200 (%s)", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"enabled":true`) || !strings.Contains(body, `"coord":"coord:7014"`) {
		t.Fatalf("status body: %s", body)
	}

	// Local pause → the endpoint reports 200 with paused:true (so the SPA can
	// offer a Start), distinct from the "never enrolled" 404.
	_ = c.MeshDown()
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/v1/mesh", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"paused":true`) {
		t.Fatalf("after mesh down /v1/mesh = %d body %s, want 200 + paused:true", rr.Code, rr.Body.String())
	}
}

// The local console is for the person standing AT the machine, and the case
// they alone can fix is "bound to 127.0.0.1". So the self-check has to reach
// this list — and so do the services a manager registered in the web console,
// which this machine never declared but does check.
func TestMeshServicesCarryTheSelfCheckAndConsoleEntries(t *testing.T) {
	c := newTestController(nil)
	c.services = []meshServiceDecl{{Name: "db", Proto: "tcp", Port: 5432}}
	c.lease = &fakeLease{obs: []mesh.ServiceObservation{
		{
			Service: mesh.DeclaredService{Name: "db", Proto: "tcp", Port: 5432},
			Health:  mesh.ServiceHealthReport{Name: "db", Checked: true, TargetOK: true, MeshOK: false},
		},
		{
			Service:    mesh.DeclaredService{Name: "web", Proto: "tcp", Port: 8080, Target: "127.0.0.1:8080"},
			Health:     mesh.ServiceHealthReport{Name: "web", Checked: true, TargetOK: true, MeshOK: true},
			FromNetmap: true,
		},
	}}

	byName := map[string]statusapi.MeshServiceDecl{}
	for _, s := range c.MeshServices() {
		byName[s.Name] = s
	}
	db, ok := byName["db"]
	if !ok {
		t.Fatal("the machine's own declaration vanished")
	}
	if !db.Checked || !db.TargetOK || db.MeshOK {
		t.Errorf("db = %+v, want the loopback-only observation", db)
	}
	if !db.FromConfig || db.FromConsole {
		t.Errorf("db source flags = config:%v console:%v", db.FromConfig, db.FromConsole)
	}
	web, ok := byName["web"]
	if !ok {
		t.Fatal("a console-registered service is invisible on the machine that serves it")
	}
	if !web.FromConsole {
		t.Error("a console-registered service was not marked as such")
	}
	if web.Port != 8080 || web.Target != "127.0.0.1:8080" {
		t.Errorf("web = %+v, want its registered endpoint", web)
	}
}

// A console-registered row must never be written into this machine's own
// declarations: the next registration would then claim the name locally too,
// leaving two rows for one service and only one of them authorized.
func TestSetMeshServicesRefusesToAdoptAConsoleEntry(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CALABI_CONFIG_DIR", dir)
	c := newTestController(func(context.Context, meshConfig, func() string) meshLease {
		return &fakeLease{}
	})
	if err := c.SetMeshServices([]statusapi.MeshServiceDecl{
		{Name: "web", Proto: "tcp", Port: 8080, FromConsole: true},
		{Name: "mine", Proto: "tcp", Port: 9000},
	}); err != nil {
		t.Fatalf("set: %v", err)
	}
	cfg, err := creds.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.MeshServices) != 1 || cfg.MeshServices[0].Name != "mine" {
		t.Fatalf("persisted %+v, want only the locally-added one", cfg.MeshServices)
	}
}

// An observation outlives the declaration it came from by one check cycle. If
// the local console worked out "registered in the web console" by subtracting
// its own declarations, a service the operator JUST removed would reappear
// labelled as somebody else's — and refuse to be removed again, since console
// rows are read-only here.
func TestRemovedServiceDoesNotComeBackAsAConsoleEntry(t *testing.T) {
	c := newTestController(nil)
	c.services = nil // the operator removed it a moment ago
	c.lease = &fakeLease{obs: []mesh.ServiceObservation{{
		Service: mesh.DeclaredService{Name: "gone", Proto: "tcp", Port: 7000},
		Health:  mesh.ServiceHealthReport{Name: "gone", Checked: true, TargetOK: true, MeshOK: true},
		// FromNetmap deliberately false: this was a LOCAL declaration.
	}}}
	for _, s := range c.MeshServices() {
		if s.Name == "gone" {
			t.Fatalf("a removed local service came back as %+v", s)
		}
	}
}
