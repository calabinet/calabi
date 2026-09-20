package main

// The local daemon connected to a self-hosted server: its mesh as something the
// console can start, stop and reconfigure, and the console's /v1/selfhosted and
// mesh-settings endpoints. Joining is signing in; the mesh is a switch on top.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/calabinet/calabi/apps/client/internal/creds"
	"github.com/calabinet/calabi/apps/client/internal/localweb"
	"github.com/calabinet/calabi/apps/client/internal/mesh"
	"github.com/calabinet/calabi/apps/client/internal/selfhosted"
	"github.com/calabinet/calabi/apps/client/internal/status"
	"github.com/calabinet/calabi/apps/client/internal/trust"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

// localMesh is the local daemon's mesh. The console changes its settings and
// starts and stops it, so the runner is rebuilt from the config rather than
// fixed at boot.
type localMesh struct {
	logger  *slog.Logger
	sv      *localSupervisor
	managed bool
	// tunnels outlives every runner: the counts it reports are the daemon's.
	tunnels *mesh.TunnelMeter
	certs   certWatch
	viewer  selfhosted.Viewer
	// enrollMu: one join by the config's key at a time (enroll).
	enrollMu sync.Mutex

	mu     sync.Mutex
	ctx    context.Context
	r      *meshRunner
	paused bool
}

// localMeshTuning is what every runner the local daemon builds starts with:
// the zero value in production; a test that runs the whole daemon keeps the
// mesh off the machine's network with it.
var localMeshTuning meshLoopTuning

func newLocalMesh(logger *slog.Logger, sv *localSupervisor, managed bool, tunnels *mesh.TunnelMeter) *localMesh {
	return &localMesh{logger: logger, sv: sv, managed: managed, tunnels: tunnels}
}

func (m *localMesh) meshCfg() meshConfig { return m.sv.config().Mesh }

// joined: this device joined a self-hosted coordinator. That is its identity
// for the edge too, so tunnels work whether or not the mesh is on.
func (m *localMesh) joined() bool { return m.meshCfg().Coord != "" }

// configured: joined, with the mesh on.
func (m *localMesh) configured() bool {
	cfg := m.meshCfg()
	return cfg.Enabled && cfg.Coord != ""
}

// build makes a runner for the current config, or nil when it cannot run one.
func (m *localMesh) build() *meshRunner {
	cfg := m.meshCfg()
	if !cfg.Enabled {
		return nil
	}
	rec := loadMeshReauth(cfg.Coord)
	// No auth key is fine for a node the coordinator takes back by proof alone:
	// the console drops the key once it has done its job.
	if cfg.Coord == "" || (cfg.AuthKey == "" && !rec.canRejoin()) {
		m.logger.Warn("mesh: enabled but coord/auth_key incomplete — not starting it")
		return nil
	}
	if _, err := cfg.coordTrust(cfg.AuthKey); err != nil {
		m.logger.Error("mesh: not starting it — the coordinator trust in the config is unusable", "err", err)
		return nil
	}
	r := newMeshRunner(m.logger, cfg)
	r.tune = localMeshTuning
	// No r.tunnels: the daemon reports its tunnels itself (reportTunnels), over
	// this runner's session while there is one and a view session otherwise.
	r.certs = &m.certs
	r.reauth = mesh.NewReauthState(rec.NodeID, rec.Reauth, m.recordReauth(cfg.Coord))
	return r
}

// recordReauth keeps which node this device is, so it comes back after a
// restart without the auth key; and once the coordinator takes it back by proof
// alone, drops the key from the console's config — a one-time invite has done
// its job, and a key in a file is one more thing a copied disk gives away. A
// hand-written config is left as written.
func (m *localMesh) recordReauth(coord string) func(int64, bool) {
	return func(nodeID int64, offered bool) {
		if err := saveMeshReauth(meshReauthRecord{Coord: coord, NodeID: nodeID, Reauth: offered}); err != nil {
			m.logger.Warn("mesh: could not save which node this device is", "err", err)
			return
		}
		if offered && m.managed && m.meshCfg().AuthKey != "" {
			if err := m.sv.updateBase(func(c *localConfig) { c.Mesh.AuthKey = "" }); err != nil {
				m.logger.Warn("mesh: could not drop the auth key from the config", "err", err)
				return
			}
			m.logger.Info("mesh: the coordinator takes this device back by its own key now; the auth key is dropped from the config")
		}
	}
}

// Start brings the mesh up for the daemon's lifetime, and starts reporting the
// daemon's tunnels to the coordinator.
func (m *localMesh) Start(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ctx = ctx
	m.startLocked()
	if m.tunnels != nil && m.joined() {
		go m.reportTunnels(ctx)
	}
}

// reportTunnels keeps the coordinator's list of this device's tunnels and their
// traffic current for as long as the daemon runs — over the mesh's session
// while it is up, and a view session while the mesh is off: the device serves
// tunnels either way. One loop
// for the daemon, so no byte is reported twice.
func (m *localMesh) reportTunnels(ctx context.Context) {
	m.tunnels.Report(ctx, mesh.TunnelReportEvery, func(ctx context.Context, reports []mesh.TunnelReport) error {
		return m.read(ctx, func(cc *mesh.CoordClient) error { return cc.ReportTunnels(ctx, reports) })
	}, func(err error) bool {
		m.logger.Debug("tunnel report failed; the next one carries its bytes", "err", err)
		return false
	})
}

func (m *localMesh) startLocked() {
	if m.paused || m.ctx == nil || m.r != nil {
		return
	}
	if r := m.build(); r != nil {
		r.Start(m.ctx)
		m.r = r
		cfg := m.meshCfg()
		m.logger.Info("mesh started", "coord", cfg.Coord, "relay", cfg.Relay)
	}
}

// Stop takes the mesh down (the daemon is ending).
func (m *localMesh) Stop() {
	m.mu.Lock()
	r := m.r
	m.r = nil
	m.mu.Unlock()
	if r != nil {
		r.Stop()
	}
}

// restart applies a changed config: the session re-registers with it.
func (m *localMesh) restart() {
	m.Stop()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.startLocked()
}

func (m *localMesh) runner() *meshRunner {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.r
}

// MeshStatus implements localweb.MeshSource.
func (m *localMesh) MeshStatus() localweb.MeshStatus {
	m.mu.Lock()
	r, paused := m.r, m.paused
	m.mu.Unlock()
	if r != nil {
		return r.MeshStatus()
	}
	cfg := m.meshCfg()
	if cfg.Coord != "" {
		// Joined with the mesh off: the console offers to turn it on.
		return localweb.MeshStatus{Enabled: true, Paused: paused || !cfg.Enabled, Coord: cfg.Coord, Peers: []localweb.MeshPeer{}}
	}
	return localweb.MeshStatus{Peers: []localweb.MeshPeer{}}
}

// ProbeRelayLeg implements localweb.MeshSource.
func (m *localMesh) ProbeRelayLeg(ctx context.Context, relay string, size int, rateMbps float64, seconds int, oneWay bool) (localweb.MeshRelayProbe, error) {
	r := m.runner()
	if r == nil {
		return localweb.MeshRelayProbe{}, errors.New("mesh is not running")
	}
	return r.ProbeRelayLeg(ctx, relay, size, rateMbps, seconds, oneWay)
}

// MeshDown implements localweb.MeshSource: leave the meshnet — no network
// interface, not a peer on the other devices — and stay joined, so tunnels keep
// working. The console's own config remembers it across restarts; a
// hand-written one is left as written, and the mesh comes back with the daemon.
func (m *localMesh) MeshDown() error {
	m.mu.Lock()
	m.paused = true
	m.mu.Unlock()
	m.Stop()
	if m.managed && m.meshCfg().Enabled {
		if err := m.sv.updateBase(func(c *localConfig) { c.Mesh.Enabled = false }); err != nil {
			m.logger.Warn("mesh: stopped, but could not save that it is off; it comes back with the daemon", "err", err)
		}
	}
	return nil
}

// MeshUp turns the mesh on, after MeshDown or on a device that joined with it
// off.
func (m *localMesh) MeshUp() error {
	cfg := m.meshCfg()
	switch {
	case cfg.Coord == "":
		return errors.New("this device has not joined a self-hosted server")
	case !cfg.Enabled && !m.managed:
		return fmt.Errorf("the mesh is off in %s (mesh.enabled); turn it on there", m.sv.configPath)
	case !cfg.Enabled:
		if err := m.sv.updateBase(func(c *localConfig) { c.Mesh.Enabled = true }); err != nil {
			return fmt.Errorf("save: %w", err)
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.paused = false
	m.startLocked()
	return nil
}

// coordCert is the coordinator certificate problem to show, if any: the
// runner's, or with the mesh off, what a view session ran into (noteReadFailure).
func (m *localMesh) coordCert() (presented, pinned string) {
	if r := m.runner(); r != nil {
		return r.coordCert()
	}
	return m.certs.get()
}

// state is the mesh's condition in a word, for the console.
func (m *localMesh) state() string {
	m.mu.Lock()
	r, paused := m.r, m.paused
	m.mu.Unlock()
	switch {
	case paused:
		return "paused"
	case r == nil:
		return "off" // switched off, or it could not start (the log says why)
	case r.liveCoord() != nil:
		return "connected"
	}
	if p, _ := r.coordCert(); p != "" {
		return "cert_changed"
	}
	r.mu.Lock()
	err := r.lastErr
	r.mu.Unlock()
	switch grpcCode(err) {
	case codes.NotFound, codes.FailedPrecondition, codes.Unauthenticated:
		// The coordinator no longer takes this device: deleted, signed out, or
		// its key revoked. Only a new invite brings it back.
		return "needs_invite"
	case codes.PermissionDenied:
		return "disabled"
	}
	return "connecting"
}

// grpcCode is the gRPC code somewhere in err's chain; OK for nil, Unknown for
// an error that carries none.
func grpcCode(err error) codes.Code {
	if err == nil {
		return codes.OK
	}
	var se interface{ GRPCStatus() *grpcstatus.Status }
	if errors.As(err, &se) {
		return se.GRPCStatus().Code()
	}
	return codes.Unknown
}

// viewNode is who this device is on the coordinator, for a view session.
func (m *localMesh) viewNode() (selfhosted.Node, error) { return selfHostedNode(m.meshCfg()) }

// nodeKey is this device's node key: its identity on the coordinator, and what
// answers its edge's challenge.
func (m *localMesh) nodeKey() (mesh.PrivateKey, error) { return meshNodeKey(m.meshCfg()) }

// selfHostedNode is who this device is on the coordinator in cfg, for a view
// session.
func selfHostedNode(cfg meshConfig) (selfhosted.Node, error) {
	t, err := cfg.coordTrust(cfg.AuthKey)
	if err != nil {
		return selfhosted.Node{}, err
	}
	rec := loadMeshReauth(cfg.Coord)
	priv, err := meshNodeKey(cfg)
	if err != nil {
		return selfhosted.Node{}, err
	}
	return selfhosted.Node{Server: cfg.Coord, Trust: t, NodeID: rec.NodeID, Reauth: rec.Reauth, Key: priv}, nil
}

// meshNodeKey is this device's node key, from the file cfg names.
func meshNodeKey(cfg meshConfig) (mesh.PrivateKey, error) {
	keyFile := cfg.KeyFile
	if keyFile == "" {
		keyFile = defaultMeshKeyPath()
	}
	return mesh.LoadOrCreateKey(keyFile)
}

var errNoMesh = errors.New("this device is not connected to a self-hosted coordinator")

// read runs read against the coordinator: over the live session, or a view
// session when the mesh is off or not connected.
func (m *localMesh) read(ctx context.Context, read func(*mesh.CoordClient) error) error {
	if !m.joined() {
		return errNoMesh
	}
	var live *mesh.CoordClient
	r := m.runner()
	if r != nil {
		live = r.liveCoord()
	}
	err := m.viewer.Read(ctx, live, m.viewNode, read)
	if r == nil && errors.Is(err, selfhosted.ErrCannotView) && m.meshCfg().AuthKey != "" {
		// A hand-written config whose device never joined, with its mesh off:
		// nothing else will join it with the key, and the edge needs it joined.
		if err = m.enroll(ctx); err == nil {
			err = m.viewer.Read(ctx, nil, m.viewNode, read)
		}
	}
	if r == nil {
		m.noteReadFailure(ctx, err)
	}
	return err
}

// enroll joins the coordinator with the config's auth key and keeps the record
// later view sessions prove. Done once: it returns at once when the device can
// already come back by proof.
func (m *localMesh) enroll(ctx context.Context) error {
	m.enrollMu.Lock()
	defer m.enrollMu.Unlock()
	cfg := m.meshCfg()
	if loadMeshReauth(cfg.Coord).canRejoin() {
		return nil
	}
	t, err := cfg.coordTrust(cfg.AuthKey)
	if err != nil {
		return err
	}
	priv, err := meshNodeKey(cfg)
	if err != nil {
		return err
	}
	conn, err := dialCoord(cfg.Coord, t)
	if err != nil {
		return err
	}
	defer conn.Close()
	reg, err := mesh.NewCoordClient(conn).Register(ctx, mesh.RegisterParams{
		AuthKey: cfg.AuthKey, NodeKey: priv.Public(), NodePrivate: priv, Name: meshNodeName(cfg),
	})
	if err != nil {
		return err
	}
	m.logger.Info("joined the self-hosted coordinator with the config's key", "coord", cfg.Coord, "node_id", reg.NodeID)
	m.recordReauth(cfg.Coord)(reg.NodeID, reg.Capabilities.Supports(meshproto.CapNodeReauth))
	return nil
}

// noteReadFailure watches the coordinator's certificate while the mesh is off,
// which the runner does while it is on: a read that could not reach the
// coordinator checks whether its certificate stopped matching — only a person
// can accept a new one, in the console.
func (m *localMesh) noteReadFailure(ctx context.Context, err error) {
	switch {
	case err == nil:
		m.certs.clear()
		return
	case grpcCode(err) != codes.Unavailable:
		return
	}
	cfg := m.meshCfg()
	t, terr := cfg.coordTrust(cfg.AuthKey)
	if terr != nil || t.Mode == trust.Plaintext {
		return
	}
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	presented := selfhosted.CertRefused(pctx, cfg.Coord, t, selfhosted.CoordALPN)
	if presented == "" {
		m.certs.clear()
		return
	}
	if was, _ := m.certs.get(); was != presented {
		m.logger.Warn("the coordinator presents a certificate this device does not trust; confirm it in the console",
			"coord", cfg.Coord, "presented", presented, "trust", t.Mode)
	}
	m.certs.set(presented, firstPin(t))
}

// signOut tells the coordinator this device left, so proof of its key alone no
// longer brings it back. Best effort: an unreachable server must not keep the
// device joined.
func (m *localMesh) signOut(ctx context.Context) error {
	cfg := m.meshCfg()
	return m.signOutWith(ctx, cfg, loadMeshReauth(cfg.Coord))
}

// signOutWith is signOut for the coordinator in cfg, as the node in rec.
func (m *localMesh) signOutWith(ctx context.Context, cfg meshConfig, rec meshReauthRecord) error {
	if cfg.Coord == "" {
		return nil
	}
	if r := m.runner(); r != nil && r.cfg.Coord == cfg.Coord {
		if live := r.liveCoord(); live != nil {
			return live.SignOut(ctx)
		}
	}
	return coordSignOut(ctx, cfg, rec)
}

// coordSignOut opens a session — by proof alone, or with the key — just to end
// it with SignOut.
func coordSignOut(ctx context.Context, cfg meshConfig, rec meshReauthRecord) error {
	t, err := cfg.coordTrust(cfg.AuthKey)
	if err != nil {
		return err
	}
	priv, err := meshNodeKey(cfg)
	if err != nil {
		return err
	}
	conn, err := dialCoord(cfg.Coord, t)
	if err != nil {
		return err
	}
	defer conn.Close()
	cc := mesh.NewCoordClient(conn)
	if _, err := cc.Register(ctx, mesh.RegisterParams{
		AuthKey: cfg.AuthKey, NodeKey: priv.Public(), NodePrivate: priv, Name: meshNodeName(cfg),
		NodeID: rec.NodeID, Reauth: rec.canRejoin(),
	}); err != nil {
		return err
	}
	return cc.SignOut(ctx)
}

func meshNodeName(cfg meshConfig) string {
	if cfg.Name != "" {
		return cfg.Name
	}
	return defaultNodeName()
}

// --- the console's endpoints ---------------------------------------------------

// localSelfHosted serves /v1/selfhosted and the mesh settings on the local
// daemon.
type localSelfHosted struct {
	logger *slog.Logger
	sv     *localSupervisor
	mesh   *localMesh
	state  *status.State
	// managed: the config is the console's own (no --config), so the console
	// may connect it elsewhere or leave. forced: this process cannot become the
	// platform daemon (--local, or CALABI_MODE in the environment).
	managed bool
	forced  bool
}

func (h *localSelfHosted) register(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/selfhosted", h.handleStatus)
	mux.HandleFunc("POST /v1/selfhosted/join", h.withToken(h.handleJoin))
	mux.HandleFunc("POST /v1/selfhosted/trust", h.withToken(h.handleTrust))
	mux.HandleFunc("POST /v1/selfhosted/leave", h.withToken(h.handleLeave))
	mux.HandleFunc("GET /v1/selfhosted/tunnels", h.handleTunnels)
	mux.HandleFunc("GET /v1/selfhosted/usage", h.handleUsage)
	mux.HandleFunc("GET /v1/mesh/nodes", h.handleNodes)
	mux.HandleFunc("POST /v1/mesh/up", h.withToken(h.handleMeshUp))
	mux.HandleFunc("GET /v1/mesh/advertise", h.handleAdvertiseGet)
	mux.HandleFunc("POST /v1/mesh/advertise", h.withToken(h.handleAdvertiseSet))
	mux.HandleFunc("GET /v1/mesh/services", h.handleServicesGet)
	mux.HandleFunc("POST /v1/mesh/services", h.withToken(h.handleServicesSet))
}

func (h *localSelfHosted) withToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("X-Local-Token")
		if got == "" {
			got = r.URL.Query().Get("local_token")
		}
		if !creds.CompareLocalToken(got) {
			shError(w, http.StatusUnauthorized, "local_token", "local-token mismatch (fetch /v1/local-token)", nil)
			return
		}
		next(w, r)
	}
}

func (h *localSelfHosted) handleStatus(w http.ResponseWriter, _ *http.Request) {
	cfg := h.sv.config()
	out := map[string]any{
		"mode":        "self_hosted",
		"managed":     h.managed,
		"can_join":    h.managed,
		"can_leave":   h.managed && !h.forced,
		"config_path": h.sv.configPath,
		"tunnels":     len(cfg.Tunnels),
	}
	if cfg.Mesh.Coord != "" {
		mesh := map[string]any{"server": cfg.Mesh.Coord, "state": h.mesh.state()}
		if t, err := cfg.Mesh.coordTrust(cfg.Mesh.AuthKey); err == nil {
			mesh["trust"] = t.Mode
			if len(t.Pins) > 0 {
				mesh["pins"] = t.Pins
			}
		}
		rec := loadMeshReauth(cfg.Mesh.Coord)
		mesh["node_id"], mesh["reauth"] = rec.NodeID, rec.Reauth
		if presented, pinned := h.mesh.coordCert(); presented != "" {
			mesh["cert_presented"], mesh["cert_pinned"] = presented, pinned
		}
		out["mesh"] = mesh
		// The edge the coordinator named, for this device's tunnels.
		out["edge"] = h.sv.edgeStatus(h.state.SnapshotNow().Connected)
	}
	shJSON(w, http.StatusOK, out)
}

// handleJoin connects this device to (another) self-hosted server. Only for the
// console's own config.
func (h *localSelfHosted) handleJoin(w http.ResponseWriter, r *http.Request) {
	if !h.managed {
		shError(w, http.StatusConflict, "not_managed", "this daemon runs a config given on its command line; edit that file instead", nil)
		return
	}
	var in joinRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 16*1024)).Decode(&in); err != nil {
		shError(w, http.StatusBadRequest, "bad_input", "parse: "+err.Error(), nil)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	cur := h.sv.config()
	// Read before joining: a new coordinator's record replaces it.
	oldRec := loadMeshReauth(cur.Mesh.Coord)
	next, fail := joinSelfHosted(ctx, cur, in)
	if fail != nil {
		shJSON(w, fail.status, fail.body)
		return
	}
	// A coordinator replaced by another: tell the old one this device left.
	if cur.Mesh.Coord != "" && cur.Mesh.Coord != next.Mesh.Coord {
		sctx, scancel := context.WithTimeout(r.Context(), 8*time.Second)
		if err := h.mesh.signOutWith(sctx, cur.Mesh, oldRec); err != nil {
			h.logger.Warn("could not tell the previous coordinator this device left; switching anyway", "err", err)
		}
		scancel()
	}
	if err := h.sv.updateBase(func(c *localConfig) {
		tunnels := c.Tunnels
		*c = next
		c.Tunnels = tunnels
	}); err != nil {
		shError(w, http.StatusInternalServerError, "save", "save: "+err.Error(), nil)
		return
	}
	h.logger.Info("self-hosted connection changed in the console; restarting the daemon to apply it")
	requestDaemonRestart(300 * time.Millisecond)
	shJSON(w, http.StatusOK, map[string]any{"switching": true})
}

// handleTrust is POST /v1/selfhosted/trust {"part": "mesh", "pin"}: the person
// compared the certificate the coordinator presents now with what it prints
// (`calabi-coord fingerprint`), and it is the coordinator's. The pin has to be
// the one presented at this moment — a confirmation covers what was shown and
// nothing else. The edge has no such step: the coordinator tells the device
// its certificate.
func (h *localSelfHosted) handleTrust(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Part string `json:"part"`
		Pin  string `json:"pin"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4*1024)).Decode(&in); err != nil {
		shError(w, http.StatusBadRequest, "bad_input", "parse: "+err.Error(), nil)
		return
	}
	pin, err := meshproto.ParseCertPin(strings.TrimSpace(in.Pin))
	if err != nil {
		shError(w, http.StatusBadRequest, "bad_input", err.Error(), nil)
		return
	}
	if in.Part != "mesh" && in.Part != "" {
		shError(w, http.StatusBadRequest, "bad_input", `part must be "mesh"`, nil)
		return
	}
	in.Part = "mesh"
	server := h.sv.config().Mesh.Coord
	if server == "" {
		shError(w, http.StatusConflict, "not_joined", "this device has not joined a self-hosted server", nil)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	pr, err := selfhosted.ProbeServer(ctx, server, selfhosted.CoordALPN)
	switch {
	case err != nil:
		shError(w, http.StatusBadGateway, "unreachable", err.Error(), map[string]any{"part": in.Part})
		return
	case !pr.TLS:
		shError(w, http.StatusConflict, "no_tls", "the server does not use TLS", map[string]any{"part": in.Part})
		return
	case pr.Pin != pin:
		shError(w, http.StatusConflict, "pin_mismatch", "the server presents another certificate now",
			map[string]any{"part": in.Part, "pin": pr.Pin})
		return
	}
	if err := h.sv.updateBase(func(c *localConfig) {
		c.Mesh.Trust, c.Mesh.Pins, c.Mesh.CAFile = "pin", []string{pin}, ""
	}); err != nil {
		shError(w, http.StatusInternalServerError, "save", "save: "+err.Error(), nil)
		return
	}
	h.logger.Warn("the coordinator's new certificate was confirmed in the console", "server", server, "pin", pin)
	h.mesh.certs.clear()
	h.mesh.viewer.Drop() // dialled with the trust just replaced
	h.mesh.restart()
	// The edge comes from the coordinator: try it again now, not at the end of
	// the back-off.
	select {
	case h.sv.retryNow <- struct{}{}:
	default:
	}
	shJSON(w, http.StatusOK, map[string]any{"part": in.Part, "server": server, "pin": pin})
}

// handleLeave disconnects this device from its self-hosted server and forgets
// it: the coordinator is told it left, the console's config goes (tunnels
// defined in it with it), and the daemon starts again as calabi.net's, at the
// sign-in page. The mesh key stays — it is this machine's, not the server's.
func (h *localSelfHosted) handleLeave(w http.ResponseWriter, r *http.Request) {
	switch {
	case !h.managed:
		shError(w, http.StatusConflict, "not_managed", "this daemon runs a config given on its command line; stop it and start the daemon without --config", nil)
		return
	case h.forced:
		shError(w, http.StatusConflict, "mode_forced", "this daemon is held in self-hosted mode (--local or CALABI_MODE)", nil)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	if err := h.mesh.signOut(ctx); err != nil {
		h.logger.Warn("could not tell the coordinator this device left; forgetting it anyway", "err", err)
	}
	cancel()
	h.mesh.Stop()
	if err := os.Remove(h.sv.configPath); err != nil && !os.IsNotExist(err) {
		shError(w, http.StatusInternalServerError, "save", "remove the config: "+err.Error(), nil)
		return
	}
	forgetMeshReauth()
	if err := setClientMode(""); err != nil {
		shError(w, http.StatusInternalServerError, "save", "save the mode: "+err.Error(), nil)
		return
	}
	h.logger.Info("left the self-hosted server; starting again as the calabi.net daemon")
	requestDaemonRestart(300 * time.Millisecond)
	shJSON(w, http.StatusOK, map[string]any{"switching": true})
}

// setClientMode persists the client mode ("" = calabi.net).
func setClientMode(mode string) error {
	c, err := creds.Load()
	if err != nil || c == nil {
		c = &creds.Config{}
	}
	c.Mode = mode
	return creds.Save(c)
}

// readFailure answers a read the coordinator refused or could not serve.
func readFailure(w http.ResponseWriter, err error) {
	if errors.Is(err, errNoMesh) {
		shError(w, http.StatusConflict, "no_mesh", err.Error(), nil)
		return
	}
	st, code := selfhosted.ReadFailure(err)
	shError(w, st, code, err.Error(), nil)
}

// handleNodes is GET /v1/mesh/nodes: the meshnet's devices from the
// coordinator, in the shape the mesh page reads for the platform.
func (h *localSelfHosted) handleNodes(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	var nodes []mesh.NodeInfo
	if err := h.mesh.read(ctx, func(cc *mesh.CoordClient) (err error) {
		nodes, err = cc.ListNodes(ctx)
		return err
	}); err != nil {
		readFailure(w, err)
		return
	}
	items := make([]map[string]any, 0, len(nodes))
	for _, n := range nodes {
		item := map[string]any{
			"id": n.ID, "name": n.Name, "overlay": n.Overlay, "os": n.OS, "owner_user_id": 0,
			"online": n.Online, "approved": n.Approved, "disabled": n.Disabled,
		}
		if !n.LastSeen.IsZero() {
			item["last_seen"] = n.LastSeen.UTC().Format(time.RFC3339)
		}
		items = append(items, item)
	}
	shJSON(w, http.StatusOK, map[string]any{"items": items})
}

// handleTunnels is GET /v1/selfhosted/tunnels: every tunnel the meshnet's
// daemons reported, this one's included.
func (h *localSelfHosted) handleTunnels(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	var list []mesh.TunnelInfo
	if err := h.mesh.read(ctx, func(cc *mesh.CoordClient) (err error) {
		list, err = cc.ListTunnels(ctx)
		return err
	}); err != nil {
		readFailure(w, err)
		return
	}
	items := make([]map[string]any, 0, len(list))
	for _, t := range list {
		// A device that is not connected may no longer serve what it reported.
		st := t.Status
		if !t.NodeOnline {
			st = "offline"
		}
		item := map[string]any{
			"id": t.ID, "name": t.Name, "type": t.Type, "public_addr": t.PublicAddr, "local_addr": t.LocalAddr,
			"status": st, "node_id": t.NodeID, "node_name": t.NodeName, "node_online": t.NodeOnline,
			"traffic_30d": t.Traffic30d, "first_seen": t.FirstSeen.UTC().Format(time.RFC3339),
		}
		if !t.ReportedAt.IsZero() {
			item["reported_at"] = t.ReportedAt.UTC().Format(time.RFC3339)
		}
		items = append(items, item)
	}
	shJSON(w, http.StatusOK, map[string]any{"items": items})
}

// handleUsage is GET /v1/selfhosted/usage?tz=&days=: the meshnet's traffic,
// month and days in the viewer's time zone (the page passes the browser's).
func (h *localSelfHosted) handleUsage(w http.ResponseWriter, r *http.Request) {
	days := 7
	if v := r.URL.Query().Get("days"); v != "" {
		if n, err := parsePositive(v); err == nil && n <= 31 {
			days = n
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	var u mesh.Usage
	if err := h.mesh.read(ctx, func(cc *mesh.CoordClient) (err error) {
		u, err = cc.GetUsage(ctx, r.URL.Query().Get("tz"), days)
		return err
	}); err != nil {
		readFailure(w, err)
		return
	}
	out := map[string]any{
		"devices": map[string]any{"used": u.DevicesUsed, "disabled": u.DevicesDisabled, "limit": u.DevicesLimit},
	}
	if u.Unavailable != "" {
		out["unavailable"] = u.Unavailable
	}
	if u.RelayNotRecorded {
		out["relay_not_recorded"] = true
	}
	if m := u.Month; m != nil {
		out["month"] = map[string]any{
			"tunnel_bytes": m.TunnelBytes, "relay_bytes": m.RelayBytes,
			"from": m.From.UTC().Format(time.RFC3339), "to": m.To.UTC().Format(time.RFC3339),
		}
	}
	list := make([]map[string]any, 0, len(u.Days))
	for _, d := range u.Days {
		list = append(list, map[string]any{"start": d.Start.UTC().Format(time.RFC3339), "bytes": d.Bytes})
	}
	out["days"] = list
	shJSON(w, http.StatusOK, out)
}

func (h *localSelfHosted) handleMeshUp(w http.ResponseWriter, _ *http.Request) {
	if err := h.mesh.MeshUp(); err != nil {
		shError(w, http.StatusConflict, "no_mesh", err.Error(), nil)
		return
	}
	shJSON(w, http.StatusOK, map[string]any{"status": "up"})
}

// handleAdvertiseGet is GET /v1/mesh/advertise, the shape the platform daemon
// serves, from the config's mesh block.
func (h *localSelfHosted) handleAdvertiseGet(w http.ResponseWriter, _ *http.Request) {
	shJSON(w, http.StatusOK, h.advertise(h.mesh.meshCfg()))
}

func (h *localSelfHosted) advertise(cfg meshConfig) map[string]any {
	accept := false
	if cfg.AcceptRoutes != nil {
		accept = *cfg.AcceptRoutes
	} else if c, err := creds.Load(); err == nil && c != nil && c.MeshAcceptRoutes != nil {
		accept = *c.MeshAcceptRoutes
	}
	out := map[string]any{
		"routes":               nonNil(cfg.AdvertiseRoutes),
		"advertise_exit_node":  cfg.AdvertiseExitNode,
		"exit_node":            cfg.ExitNode,
		"forwarding_supported": mesh.SubnetRouterSupported(),
		"accept_routes":        accept,
		"route_excludes":       nonNil(cfg.RouteExcludes),
		"block_incoming":       cfg.BlockIncoming,
	}
	if support, _ := mesh.SubnetAliasSupport(h.logger); support != mesh.AliasSupportUnknown {
		out["alias_supported"] = support == mesh.AliasSupportYes
	}
	return out
}

// handleAdvertiseSet is POST /v1/mesh/advertise: the same rules as the
// platform daemon's, written to the config's mesh block, applied by
// re-registering.
func (h *localSelfHosted) handleAdvertiseSet(w http.ResponseWriter, r *http.Request) {
	if !h.mesh.configured() {
		shError(w, http.StatusConflict, "no_mesh", errNoMesh.Error(), nil)
		return
	}
	var in struct {
		Routes        []string  `json:"routes"`
		ExitNode      bool      `json:"advertise_exit_node"`
		ExitPeer      string    `json:"exit_node"`
		AcceptRoutes  *bool     `json:"accept_routes"`
		RouteExcludes *[]string `json:"route_excludes"`
		BlockIncoming *bool     `json:"block_incoming"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16*1024)).Decode(&in); err != nil {
		shError(w, http.StatusBadRequest, "bad_input", "parse: "+err.Error(), nil)
		return
	}
	routes := make([]string, 0, len(in.Routes))
	for _, raw := range in.Routes {
		if raw = strings.TrimSpace(raw); raw == "" {
			continue
		}
		p, err := mesh.ParseRoute(raw)
		if err != nil {
			shError(w, http.StatusBadRequest, "bad_input", "invalid route: "+err.Error(), nil)
			return
		}
		routes = append(routes, p.String())
	}
	var excludes []string
	if in.RouteExcludes != nil {
		excludes = []string{}
		for _, raw := range *in.RouteExcludes {
			if raw = strings.TrimSpace(raw); raw == "" {
				continue
			}
			p, err := mesh.ParseExclude(raw)
			if err != nil {
				shError(w, http.StatusBadRequest, "bad_input", "invalid excluded route: "+err.Error(), nil)
				return
			}
			excludes = append(excludes, p.String())
		}
	}
	cur := h.mesh.meshCfg()
	// No NEW forwarding role where this host cannot forward: peers would route
	// into a dead end. Giving one up, or saving with it unchanged, always works.
	if !mesh.SubnetRouterSupported() {
		had := map[string]bool{}
		for _, r := range cur.AdvertiseRoutes {
			if p, err := mesh.ParseRoute(r); err == nil {
				had[p.String()] = true
			}
		}
		for _, r := range routes {
			if !had[r] {
				shError(w, http.StatusBadRequest, "bad_input", "this device cannot forward traffic (subnet routing is Linux-only), so it cannot advertise "+r, nil)
				return
			}
		}
		if in.ExitNode && !cur.AdvertiseExitNode {
			shError(w, http.StatusBadRequest, "bad_input", "this device cannot forward traffic (exit nodes are Linux-only), so it cannot offer itself as an exit node", nil)
			return
		}
	}
	if err := h.sv.updateBase(func(c *localConfig) {
		c.Mesh.AdvertiseRoutes, c.Mesh.AdvertiseExitNode, c.Mesh.ExitNode = routes, in.ExitNode, strings.TrimSpace(in.ExitPeer)
		if in.AcceptRoutes != nil {
			v := *in.AcceptRoutes
			c.Mesh.AcceptRoutes = &v
		}
		if in.RouteExcludes != nil {
			c.Mesh.RouteExcludes = excludes
		}
		if in.BlockIncoming != nil {
			c.Mesh.BlockIncoming = *in.BlockIncoming
		}
	}); err != nil {
		shError(w, http.StatusInternalServerError, "save", "save: "+err.Error(), nil)
		return
	}
	h.mesh.restart()
	next := h.mesh.meshCfg()
	h.logger.Info("mesh settings changed in the console", "routes", next.AdvertiseRoutes, "exit_node", next.ExitNode,
		"advertise_exit_node", next.AdvertiseExitNode, "block_incoming", next.BlockIncoming)
	shJSON(w, http.StatusOK, h.advertise(next))
}

// handleServicesGet is GET /v1/mesh/services: what the config declares, with
// this machine's own last check, and services a manager registered on the
// coordinator (read-only here).
func (h *localSelfHosted) handleServicesGet(w http.ResponseWriter, _ *http.Request) {
	cfg := h.mesh.meshCfg()
	var obs []mesh.ServiceObservation
	if r := h.mesh.runner(); r != nil {
		obs = r.ServiceObservations()
	}
	health := make(map[string]mesh.ServiceHealthReport, len(obs))
	for _, o := range obs {
		health[o.Service.Name] = o.Health
	}
	items := make([]map[string]any, 0, len(cfg.Services))
	declared := map[string]bool{}
	for _, s := range cfg.Services {
		declared[s.Name] = true
		proto := s.Proto
		if proto == "" {
			proto = "tcp"
		}
		hh := health[s.Name]
		items = append(items, map[string]any{
			"name": s.Name, "proto": proto, "port": s.Port, "target": s.Target, "note": s.Note,
			"checked": hh.Checked, "target_ok": hh.TargetOK, "mesh_ok": hh.MeshOK,
		})
	}
	for _, o := range obs {
		if !o.FromNetmap || declared[o.Service.Name] {
			continue
		}
		items = append(items, map[string]any{
			"name": o.Service.Name, "proto": o.Service.Proto, "port": o.Service.Port, "target": o.Service.Target,
			"from_console": true, "checked": o.Health.Checked, "target_ok": o.Health.TargetOK, "mesh_ok": o.Health.MeshOK,
		})
	}
	shJSON(w, http.StatusOK, map[string]any{"items": items})
}

// handleServicesSet is POST /v1/mesh/services {"items": [...]}: replaces what
// the config declares, and re-declares it on the running session.
func (h *localSelfHosted) handleServicesSet(w http.ResponseWriter, r *http.Request) {
	if !h.mesh.configured() {
		shError(w, http.StatusConflict, "no_mesh", errNoMesh.Error(), nil)
		return
	}
	var in struct {
		Items []struct {
			Name        string `json:"name"`
			Proto       string `json:"proto"`
			Port        int    `json:"port"`
			Target      string `json:"target"`
			Note        string `json:"note"`
			FromConsole bool   `json:"from_console"`
		} `json:"items"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16*1024)).Decode(&in); err != nil {
		shError(w, http.StatusBadRequest, "bad_input", "parse: "+err.Error(), nil)
		return
	}
	decls := make([]meshServiceDecl, 0, len(in.Items))
	seen := map[string]bool{}
	for _, d := range in.Items {
		if d.FromConsole {
			continue // the coordinator's, not this file's
		}
		name := meshproto.NormalizeLabel(d.Name)
		proto := strings.ToLower(strings.TrimSpace(d.Proto))
		if proto == "" {
			proto = "tcp"
		}
		if err := meshproto.ValidateLabel(name); err != nil {
			shError(w, http.StatusBadRequest, "bad_input", "service name: "+strings.TrimPrefix(err.Error(), "invalid label: "), nil)
			return
		}
		if proto != "tcp" && proto != "udp" {
			shError(w, http.StatusBadRequest, "bad_input", "service "+name+": proto must be tcp or udp", nil)
			return
		}
		if d.Port < 1 || d.Port > 65535 {
			shError(w, http.StatusBadRequest, "bad_input", "service "+name+": port must be 1-65535", nil)
			return
		}
		if seen[name] {
			shError(w, http.StatusBadRequest, "bad_input", "service "+name+" is listed twice", nil)
			return
		}
		seen[name] = true
		decls = append(decls, meshServiceDecl{Name: name, Proto: proto, Port: d.Port, Target: strings.TrimSpace(d.Target), Note: strings.TrimSpace(d.Note)})
	}
	if err := h.sv.updateBase(func(c *localConfig) { c.Mesh.Services = decls }); err != nil {
		shError(w, http.StatusInternalServerError, "save", "save: "+err.Error(), nil)
		return
	}
	if rr := h.mesh.runner(); rr != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		err := rr.UpdateDeclarations(ctx, declaredServices(decls), resolveFingerprint(h.logger))
		cancel()
		if err != nil {
			// Not registered right now, or the coordinator refused the update:
			// the next registration carries the new set.
			h.mesh.restart()
		}
	}
	h.handleServicesGet(w, r)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func parsePositive(s string) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("not a number")
		}
		n = n*10 + int(c-'0')
		if n > 1_000_000 {
			return 0, errors.New("too large")
		}
	}
	if n <= 0 {
		return 0, errors.New("not positive")
	}
	return n, nil
}

func shJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// shError is an error the console tells apart by code.
func shError(w http.ResponseWriter, code int, errCode, msg string, extra map[string]any) {
	body := map[string]any{"error": msg, "code": errCode}
	for k, v := range extra {
		body[k] = v
	}
	shJSON(w, code, body)
}
