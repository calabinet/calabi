// Package localweb serves the daemon SPA's /v1/* API LOCALLY for the
// self-hosted (standalone) local supervisor daemon — no bff-console proxy, no
// account, no control plane. It's the standalone counterpart to
// internal/platform/statusapi: same JSON shapes the SPA already understands, but
// sourced from the local config + runtime instead of a managed backend.
//
// Read surface: /v1/me reports a standalone identity (plan.code="standalone") so
// AuthGate renders; /v1/tunnels lists the configured tunnels (live, from the
// supervisor); /v1/inspect/* shows connections + HTTP captures from the daemon's
// inspector. Write surface: create / delete / edit-security route through
// the supervisor (live reconcile + YAML persistence), gated by the local-token.
// A nil Writer (or a read-only deployment) makes the writes return 501. The
// platform endpoints the SPA polls on load (orgs/edges/usage/clients/affinity)
// return benign empty stubs so those pages render and their platform-only chips
// hide.
package localweb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/calabi/calabi/apps/client/internal/creds"
	"github.com/calabi/calabi/apps/client/internal/inspect"
	"github.com/calabi/calabi/apps/client/internal/probe"
	"golang.org/x/crypto/bcrypt"
)

// ErrTunnelNotFound is returned by a Writer when the target tunnel id is unknown
// (mapped to HTTP 404).
var ErrTunnelNotFound = errors.New("tunnel not found")

// InspectorSource is the slice of the daemon's request inspector localweb needs
// for /v1/inspect/*. Mirrors statusapi.InspectorSource so the same
// *daemonInspector satisfies both. nil disables the inspect endpoints (503).
type InspectorSource interface {
	SnapshotConnections(proxyID string) []inspect.Connection
	SnapshotCaptures(proxyID string) []inspect.HTTPCapture
}

// Lister provides the current tunnel list for /v1/tunnels. The supervisor
// implements it so the list reflects live console edits.
type Lister interface {
	Tunnels() []ConfiguredTunnel
}

// Writer applies console mutations. nil = read-only (writes return 501). The
// supervisor implements it (live reconcile + YAML persistence).
type Writer interface {
	CreateTunnel(spec TunnelSpec) (int64, error)
	DeleteTunnel(id int64) error
	UpdateSecurity(id int64, configJSON string) error
	// UpdateTunnel edits a tunnel's mutable core fields. An empty string means
	// "leave unchanged"; the supervisor re-homes the tunnel when local_addr
	// changes so new connections dial the new upstream.
	UpdateTunnel(id int64, name, localAddr string) error
}

// UsageSource powers /v1/usage/current + /v1/usage/daily. The daemon's local
// meter implements it (self-hosted has no metering-svc). nil = always 0.
type UsageSource interface {
	TodayBytes() int64
	MonthBytes() int64
	// DailyBytes returns the last n days (oldest→newest, gaps filled with 0)
	// for the Overview's daily-traffic chart.
	DailyBytes(n int) []UsageDay
}

// UsageDay is one day's total transferred bytes (local date).
type UsageDay struct {
	Date  string // local "2006-01-02"
	Bytes int64
}

// HealthSource powers /v1/probe/health — the per-tunnel local-upstream
// reachability snapshot the console renders as green/red status dots. The
// daemon's *probe.Monitor implements it. nil = probing disabled (the endpoint
// reports enabled:false and the SPA shows a plain online dot instead of a
// perpetual "Probing...").
type HealthSource interface {
	Snapshot() []probe.Result
}

// MeshSource powers /v1/mesh — the Connect (WireGuard mesh) status the console
// and `calabi mesh status` render. The daemon's meshRunner implements it. nil =
// mesh not configured (the endpoint reports enabled:false).
type MeshSource interface {
	MeshStatus() MeshStatus
	// MeshDown stops the mesh subsystem (idempotent; nil if already down).
	MeshDown() error
}

// MeshStatus is the JSON shape for /v1/mesh.
type MeshStatus struct {
	Enabled bool   `json:"enabled"`
	Up      bool   `json:"up"`
	Coord   string `json:"coord,omitempty"`
	Relay   string `json:"relay,omitempty"`
	// DerpHome is the region code this node is homed on ("self-…" = the org's own
	// relay). Relay is the address; DerpHome is what tells self-hosted from
	// platform, so the console can flag "中继节点：自建".
	DerpHome string     `json:"derp_home,omitempty"`
	Name     string     `json:"name,omitempty"`
	Overlay  string     `json:"overlay,omitempty"`
	Peers    []MeshPeer `json:"peers"`
}

// MeshPeer is one peer's live state in /v1/mesh.
type MeshPeer struct {
	PublicKey        string   `json:"public_key"`
	AllowedIPs       []string `json:"allowed_ips"`
	LastHandshakeSec int64    `json:"last_handshake_sec"`
	RxBytes          int64    `json:"rx_bytes"`
	TxBytes          int64    `json:"tx_bytes"`
	// Path is "direct" when hole punching found a working peer-to-peer path,
	// "relay" when traffic goes through calabi-derp. Endpoint carries the direct
	// UDP address in the former case.
	Path     string `json:"path,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
}

// TunnelSpec is a create request. ConfigJSON is the already-transformed
// (bcrypt'd) security blob, or "".
type TunnelSpec struct {
	Name       string
	Type       string
	LocalAddr  string
	Domain     string // full host (wins over Subdomain)
	Subdomain  string // http/https prefix → resolved to <Subdomain>.<edge base_domain>
	RemotePort uint32
	ConfigJSON string
}

// ConfiguredTunnel is one tunnel projected for the /v1/tunnels list. ID must
// equal the TunnelID the daemon stamps onto the live status.TunnelInfo so the
// SPA joins /v1/tunnels.id ↔ /tunnels.tunnel_id (live bytes + proxy_id for the
// inspector).
type ConfiguredTunnel struct {
	ID         int64
	Name       string
	Type       string
	LocalAddr  string
	Domain     string // edge-ASSIGNED domain once live (falls back to config domain)
	RemotePort uint32 // edge-ASSIGNED remote port once live (TCP/UDP)
	ConfigJSON string
	EdgeNodeID int64 // SelfHostedEdgeID once live; 0 = not registered (SPA shows "—")
}

// SelfHostedEdgeID is the synthetic edge_node_id the local daemon reports for
// the one self-hosted edge it dials. The /v1/edges directory and each live
// tunnel's edge_node_id must agree on it so the SPA's Edge column resolves.
const SelfHostedEdgeID int64 = 1

// Config wires the local API to the daemon's runtime.
type Config struct {
	Lister    Lister          // current tunnel list (required)
	Writer    Writer          // mutations; nil = read-only (501)
	Inspector InspectorSource // /v1/inspect/*; nil disables
	Usage     UsageSource     // /v1/usage/current; nil → always 0
	Health    HealthSource    // /v1/probe/health; nil → enabled:false
	Mesh      MeshSource      // /v1/mesh (Connect status); nil → enabled:false
	Server    string          // edge control endpoint, shown in the synthetic /v1/edges row
	Region    string          // labels the synthetic edge; empty → "local"
}

// Server holds the local API config.
type Server struct {
	cfg Config
}

// New builds a local API server.
func New(cfg Config) *Server {
	if cfg.Region == "" {
		cfg.Region = "local"
	}
	return &Server{cfg: cfg}
}

// Register attaches the /v1/* routes onto mux. Pass Register to
// status.Server.AttachAPI. GETs are open (loopback only); writes need the
// local-token and a non-nil Writer.
func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("/v1/me", s.handleMe)
	mux.HandleFunc("/v1/local-token", s.handleLocalToken)
	mux.HandleFunc("/v1/tunnels", s.handleTunnels)     // GET list; POST create
	mux.HandleFunc("/v1/tunnels/", s.handleTunnelItem) // GET {id}; DELETE; {id}/security POST
	mux.HandleFunc("/v1/orgs", s.handleOrgs)
	mux.HandleFunc("/v1/orgs/switch", notSupported)
	mux.HandleFunc("/v1/edges", s.handleEdges)
	mux.HandleFunc("/v1/clients", s.handleClients)
	mux.HandleFunc("/v1/usage/current", s.handleUsageNow)
	mux.HandleFunc("/v1/usage/daily", s.handleUsageDaily)
	mux.HandleFunc("/v1/usage/history", s.handleUsageDaily)
	mux.HandleFunc("/v1/edge-affinity", s.handleEdgeAffinity)
	mux.HandleFunc("/v1/probe/health", s.handleProbeHealth)
	mux.HandleFunc("/v1/probe/ports", s.handleProbePorts)
	mux.HandleFunc("/v1/probe/check", s.handleProbeCheck)
	mux.HandleFunc("/v1/mesh", s.handleMesh)          // GET status
	mux.HandleFunc("/v1/mesh/down", s.handleMeshDown) // POST stop (local-token)
	mux.HandleFunc("/v1/inspect/connections", s.handleInspectConnections)
	mux.HandleFunc("/v1/inspect/captures", s.handleInspectCaptures)
	mux.HandleFunc("/v1/inspect/replay", notSupported)
	mux.HandleFunc("/v1/auth/login", notSupported)
	mux.HandleFunc("/v1/auth/logout", notSupported)
	mux.HandleFunc("/v1/config/import", s.handleConfigImport)
	mux.HandleFunc("/v1/config/export", s.handleConfigExport)
	mux.HandleFunc("/v1/edge-region", notSupported)
	mux.HandleFunc("/v1/edge-switch/dismiss", notSupported)
}

// --- /v1/me — standalone identity ------------------------------------------

// standaloneFeatures is the per-tunnel security capability map the SPA reads
// (plan.features_json) to decide which editor sections to show. It is
// build-tagged: where the advanced features (rate limit / header rewrite /
// OAuth) aren't supported they're disabled here and the SPA hides those sections.

func (s *Server) handleMe(w http.ResponseWriter, _ *http.Request) {
	type plan struct {
		Code         string `json:"code"`
		FeaturesJSON string `json:"features_json"`
		ReadOnly     bool   `json:"read_only"`
	}
	type account struct {
		User struct {
			ID    int64  `json:"id"`
			Email string `json:"email"`
		} `json:"user"`
		Org struct {
			ID   int64  `json:"id"`
			Name string `json:"name"`
		} `json:"org"`
		Plan plan `json:"plan"`
	}
	var me account
	me.User.Email = "standalone"
	me.Org.Name = "Standalone"
	// plan.code == "standalone" is the SPA's signal to hide platform-only
	// surfaces (login/logout, org/region switch). The tunnel writes stay
	// visible (the console is writable in standalone).
	me.Plan = plan{Code: "standalone", FeaturesJSON: standaloneFeatures, ReadOnly: false}
	writeJSON(w, http.StatusOK, me)
}

func (s *Server) handleLocalToken(w http.ResponseWriter, _ *http.Request) {
	tok, err := creds.LoadLocalToken()
	if err != nil || tok == "" {
		writeError(w, http.StatusServiceUnavailable, "local-token not yet minted")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": tok})
}

// --- /v1/tunnels — list + create -------------------------------------------

type remoteTunnel struct {
	ID         int64  `json:"id"`
	OrgID      int64  `json:"org_id"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	LocalAddr  string `json:"local_addr,omitempty"`
	Domain     string `json:"domain,omitempty"`
	RemotePort uint32 `json:"remote_port,omitempty"`
	Status     string `json:"status"`
	ConfigJSON string `json:"config_json,omitempty"`
	EdgeNodeID int64  `json:"edge_node_id,omitempty"`
}

func toRemote(t ConfiguredTunnel) remoteTunnel {
	return remoteTunnel{
		ID: t.ID, Name: t.Name, Type: t.Type, LocalAddr: t.LocalAddr,
		Domain: t.Domain, RemotePort: t.RemotePort, EdgeNodeID: t.EdgeNodeID,
		// "enabled" = the configured intent; the SPA overlays live/offline from
		// the /tunnels snapshot.
		Status: "enabled", ConfigJSON: t.ConfigJSON,
	}
}

func (s *Server) list() []ConfiguredTunnel {
	if s.cfg.Lister == nil {
		return nil
	}
	return s.cfg.Lister.Tunnels()
}

func (s *Server) handleTunnels(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		items := make([]remoteTunnel, 0)
		for _, t := range s.list() {
			items = append(items, toRemote(t))
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"items": items, "my_total": len(items), "team_total": len(items),
		})
	case http.MethodPost:
		if !s.requireWriter(w) || !checkLocalToken(w, r) {
			return
		}
		s.createTunnel(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) createTunnel(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name       string `json:"name"`
		Type       string `json:"type"`
		LocalAddr  string `json:"local_addr"`
		Domain     string `json:"domain"`
		Subdomain  string `json:"subdomain"`
		RemotePort uint32 `json:"remote_port"`
		ConfigJSON string `json:"config_json"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	cfgJSON, err := transformSecurityConfig(body.ConfigJSON)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	id, err := s.cfg.Writer.CreateTunnel(TunnelSpec{
		Name: body.Name, Type: body.Type, LocalAddr: body.LocalAddr,
		Domain: body.Domain, Subdomain: body.Subdomain,
		RemotePort: body.RemotePort, ConfigJSON: cfgJSON,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, remoteTunnel{
		ID: id, Name: body.Name, Type: body.Type, LocalAddr: body.LocalAddr,
		Domain: body.Domain, RemotePort: body.RemotePort, Status: "enabled", ConfigJSON: cfgJSON,
	})
}

func (s *Server) handleTunnelItem(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/v1/tunnels/")
	idStr := rest
	isSecurity := false
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		idStr = rest[:i]
		isSecurity = strings.TrimPrefix(rest[i:], "/") == "security"
	}
	id, _ := strconv.ParseInt(idStr, 10, 64)

	switch {
	case isSecurity && r.Method == http.MethodPost:
		if !s.requireWriter(w) || !checkLocalToken(w, r) {
			return
		}
		s.updateSecurity(w, r, id)
	case !isSecurity && r.Method == http.MethodGet:
		for _, t := range s.list() {
			if t.ID == id {
				writeJSON(w, http.StatusOK, toRemote(t))
				return
			}
		}
		writeError(w, http.StatusNotFound, "no such tunnel")
	case !isSecurity && r.Method == http.MethodPut:
		if !s.requireWriter(w) || !checkLocalToken(w, r) {
			return
		}
		s.updateTunnel(w, r, id)
	case !isSecurity && r.Method == http.MethodDelete:
		if !s.requireWriter(w) || !checkLocalToken(w, r) {
			return
		}
		if err := s.cfg.Writer.DeleteTunnel(id); err != nil {
			writeWriterErr(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// updateTunnel edits a tunnel's name + local_addr (PUT /v1/tunnels/{id}). The
// public endpoint (type / domain / port) is not editable in standalone either —
// mirrors the platform's edit scope.
func (s *Server) updateTunnel(w http.ResponseWriter, r *http.Request, id int64) {
	var body struct {
		Name      *string `json:"name"`
		LocalAddr *string `json:"local_addr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.Name == nil && body.LocalAddr == nil {
		writeError(w, http.StatusBadRequest, "nothing to update: provide name and/or local_addr")
		return
	}
	name, localAddr := "", ""
	if body.Name != nil {
		name = strings.TrimSpace(*body.Name)
		if name == "" {
			writeError(w, http.StatusBadRequest, "name must not be empty")
			return
		}
	}
	if body.LocalAddr != nil {
		localAddr = strings.TrimSpace(*body.LocalAddr)
		if localAddr == "" {
			writeError(w, http.StatusBadRequest, "local_addr must not be empty")
			return
		}
	}
	if err := s.cfg.Writer.UpdateTunnel(id, name, localAddr); err != nil {
		writeWriterErr(w, err)
		return
	}
	// Echo the resulting row so the SPA can refresh optimistically.
	for _, t := range s.list() {
		if t.ID == id {
			writeJSON(w, http.StatusOK, toRemote(t))
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "status": "enabled"})
}

func (s *Server) updateSecurity(w http.ResponseWriter, r *http.Request, id int64) {
	var body struct {
		ConfigJSON string `json:"config_json"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	cfgJSON, err := transformSecurityConfig(body.ConfigJSON)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.cfg.Writer.UpdateSecurity(id, cfgJSON); err != nil {
		writeWriterErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "status": "enabled", "config_json": cfgJSON})
}

// --- platform-shaped stubs (benign empties so SPA pages render) ------------

func (s *Server) handleOrgs(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": []any{}, "active_org_id": 0})
}

func (s *Server) handleEdges(w http.ResponseWriter, _ *http.Request) {
	region := s.cfg.Region
	if region == "" {
		region = "self-hosted" // SPA's Edge column needs a non-empty region to render
	}
	edge := map[string]any{
		"edge_node_id": SelfHostedEdgeID, "node_label": "self-hosted", "region": region,
		"public_addr": s.cfg.Server, "healthy": true, "owned": false,
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": []any{edge}, "owned_total": 0})
}

func (s *Server) handleClients(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": []any{}})
}

func (s *Server) handleUsageNow(w http.ResponseWriter, r *http.Request) {
	var total int64
	if s.cfg.Usage != nil {
		if r.URL.Query().Get("period") == "today" {
			total = s.cfg.Usage.TodayBytes()
		} else {
			total = s.cfg.Usage.MonthBytes() // /v1/usage/current with no period = month-to-date
		}
	}
	// limit_mb 0 = unlimited (self-hosted has no quota), so percent stays 0.
	writeJSON(w, http.StatusOK, map[string]any{
		"org_id": 0, "bytes_in": 0, "bytes_out": 0, "bytes_total": total,
		"percent_of_limit": 0, "limit_mb": 0,
	})
}

func (s *Server) handleUsageDaily(w http.ResponseWriter, r *http.Request) {
	n := 7
	if v := r.URL.Query().Get("n"); v != "" {
		if k, err := strconv.Atoi(v); err == nil && k > 0 && k <= 366 {
			n = k
		}
	}
	buckets := make([]map[string]any, 0, n)
	if s.cfg.Usage != nil {
		for _, d := range s.cfg.Usage.DailyBytes(n) {
			buckets = append(buckets, map[string]any{
				"ts": d.Date, "bytes_in": 0, "bytes_out": 0, "bytes_total": d.Bytes,
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"org_id": 0, "granularity": "day", "buckets": buckets})
}

// --- /v1/config/{export,import} — backup / restore the tunnel set ----------

// configSchemaVersion mirrors statusapi.configSchemaVersion so a file exported
// by the platform daemon and one exported here are import-compatible.
const configSchemaVersion = 1

// handleConfigExport returns the current tunnel set as the same JSON document
// the platform daemon produces: {schema_version, exported_at, tunnels:[…]}.
// Local-token gated (same as the platform) — the body carries tunnel config.
func (s *Server) handleConfigExport(w http.ResponseWriter, r *http.Request) {
	if !checkLocalToken(w, r) {
		return
	}
	items := make([]remoteTunnel, 0)
	for _, t := range s.list() {
		items = append(items, toRemote(t))
	}
	w.Header().Set("Content-Disposition", `attachment; filename="calabi-config.json"`)
	writeJSON(w, http.StatusOK, map[string]any{
		"schema_version": configSchemaVersion,
		"exported_at":    time.Now().UTC().Format(time.RFC3339),
		"tunnels":        items,
	})
}

// handleConfigImport recreates tunnels from a configExport document. ?dry_run=1
// validates + reports without writing. Each tunnel is created through the same
// Writer path as the console (so the local-upstream guard + persistence apply);
// per-row errors are collected so a partial import still reports what landed.
// config_json is passed through verbatim (already the final, bcrypt'd blob).
func (s *Server) handleConfigImport(w http.ResponseWriter, r *http.Request) {
	if !s.requireWriter(w) || !checkLocalToken(w, r) {
		return
	}
	var doc struct {
		SchemaVersion int            `json:"schema_version"`
		Tunnels       []remoteTunnel `json:"tunnels"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&doc); err != nil {
		writeError(w, http.StatusBadRequest, "parse: "+err.Error())
		return
	}
	if doc.SchemaVersion != configSchemaVersion {
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("unsupported schema_version %d (want %d)", doc.SchemaVersion, configSchemaVersion))
		return
	}
	dryRun := r.URL.Query().Get("dry_run") == "1"

	// Dedup: re-importing a backup must not duplicate tunnels. Skip any
	// incoming tunnel whose identity (name + type + local_addr) already exists,
	// and dedup repeats WITHIN the same document. A different name / local is a
	// genuinely new tunnel.
	seen := make(map[string]struct{})
	for _, t := range s.list() {
		seen[importKey(t.Name, t.Type, t.LocalAddr)] = struct{}{}
	}

	type item struct {
		Name    string `json:"name"`
		Created bool   `json:"created"`
		Skipped bool   `json:"skipped,omitempty"`
		Error   string `json:"error,omitempty"`
	}
	items := make([]item, 0, len(doc.Tunnels))
	var created, skipped int
	for _, t := range doc.Tunnels {
		it := item{Name: t.Name}
		key := importKey(t.Name, t.Type, t.LocalAddr)
		if _, dup := seen[key]; dup {
			it.Skipped = true
			skipped++
			items = append(items, it)
			continue
		}
		seen[key] = struct{}{}
		if !dryRun {
			if _, err := s.cfg.Writer.CreateTunnel(TunnelSpec{
				Name: t.Name, Type: t.Type, LocalAddr: t.LocalAddr,
				Domain: t.Domain, RemotePort: t.RemotePort, ConfigJSON: t.ConfigJSON,
			}); err != nil {
				it.Error = err.Error()
			} else {
				it.Created = true
				created++
			}
		}
		items = append(items, it)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"dry_run": dryRun, "total": len(items),
		"created": created, "skipped": skipped, "items": items,
	})
}

// importKey is the dedup identity for a tunnel on config import: name + type +
// local_addr, lowercased. Two tunnels matching all three are "the same".
func importKey(name, typ, local string) string {
	return strings.ToLower(strings.TrimSpace(name)) + "|" +
		strings.ToLower(strings.TrimSpace(typ)) + "|" +
		strings.ToLower(strings.TrimSpace(local))
}

func (s *Server) handleEdgeAffinity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		notSupported(w, r)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"affinity": "own", "prefer_platform": false})
}

func (s *Server) handleProbeHealth(w http.ResponseWriter, _ *http.Request) {
	if s.cfg.Health == nil {
		writeJSON(w, http.StatusOK, map[string]any{"items": []any{}, "enabled": false})
		return
	}
	items := s.cfg.Health.Snapshot()
	if items == nil {
		items = []probe.Result{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "enabled": true})
}

// meshOverlay is this machine's mesh address, or "" when it isn't on the mesh —
// reachability is then not probed rather than reported as false.
func (s *Server) meshOverlay() string {
	if s.cfg.Mesh == nil {
		return ""
	}
	st := s.cfg.Mesh.MeshStatus()
	if !st.Up {
		return ""
	}
	return st.Overlay
}

func (s *Server) handleProbePorts(w http.ResponseWriter, r *http.Request) {
	// Real local-port scan (dial-test 127.0.0.1 on the common dev ports +
	// $CALABI_PROBE_PORTS). Same scanner the platform daemon uses; was a stub
	// returning [] in standalone, so the Tools page looked broken.
	writeJSON(w, http.StatusOK, map[string]any{"items": probe.Scan(r.Context(), s.meshOverlay())})
}

// handleProbeCheck probes ONE address on demand — the new-tunnel wizard's
// "is my local service actually up?" check, so a tunnel that would 502 says so
// before it's created.
//
// POST because it makes the daemon dial something. probe.CheckOnce validates
// the address first: this endpoint must not become a port scanner for whoever
// can reach the local console.
//
// A failed check returns 200 with healthy:false. Creating a tunnel before
// starting the service behind it is normal — the SPA shows a hint, not an error.
func (s *Server) handleProbeCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4*1024))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	var req struct {
		Type      string `json:"type"`
		LocalAddr string `json:"local_addr"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "parse: "+err.Error())
		return
	}
	if strings.TrimSpace(req.LocalAddr) == "" {
		writeError(w, http.StatusBadRequest, "local_addr required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, probe.CheckOnce(ctx, probe.TunnelTarget{
		Type:      req.Type,
		LocalAddr: req.LocalAddr,
	}))
}

// --- /v1/mesh — Connect (WireGuard mesh) status ----------------------------

func (s *Server) handleMesh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.cfg.Mesh == nil {
		writeJSON(w, http.StatusOK, MeshStatus{Enabled: false, Peers: []MeshPeer{}})
		return
	}
	st := s.cfg.Mesh.MeshStatus()
	if st.Peers == nil {
		st.Peers = []MeshPeer{}
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleMeshDown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.cfg.Mesh == nil {
		writeError(w, http.StatusNotFound, "mesh not configured")
		return
	}
	if !checkLocalToken(w, r) {
		return
	}
	if err := s.cfg.Mesh.MeshDown(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "down"})
}

// --- /v1/inspect/* — live connections + HTTP captures ----------------------

func (s *Server) handleInspectConnections(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Inspector == nil {
		writeError(w, http.StatusServiceUnavailable, "inspector disabled")
		return
	}
	pid := r.URL.Query().Get("proxy_id")
	if pid == "" {
		writeError(w, http.StatusBadRequest, "proxy_id required")
		return
	}
	items := s.cfg.Inspector.SnapshotConnections(pid)
	if items == nil {
		items = []inspect.Connection{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleInspectCaptures(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Inspector == nil {
		writeError(w, http.StatusServiceUnavailable, "inspector disabled")
		return
	}
	pid := r.URL.Query().Get("proxy_id")
	if pid == "" {
		writeError(w, http.StatusBadRequest, "proxy_id required")
		return
	}
	items := s.cfg.Inspector.SnapshotCaptures(pid)
	if items == nil {
		items = []inspect.HTTPCapture{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// --- security transform -----------------------------------------------------

// transformSecurityConfig mirrors bff-console: it bcrypt-hashes any cleartext
// basic-auth password the SPA sends ({user, password}) into {user, hash} and
// strips the cleartext, leaving the rest of the config_json (ip / rate / headers
// / oauth) untouched. Returns "" for an empty input.
func transformSecurityConfig(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return "", errors.New("invalid config_json")
	}
	sec, ok := doc["security"].(map[string]any)
	if !ok {
		out, _ := json.Marshal(doc)
		return string(out), nil
	}
	// stripAdvancedSecurity drops the advanced blocks (rate limit / header
	// rewrite / OAuth) where they aren't supported — defense in depth behind the
	// SPA, which already hides those sections via features_json.
	stripAdvancedSecurity(sec)
	if ba, ok := sec["basic_auth"].(map[string]any); ok {
		if users, ok := ba["users"].([]any); ok {
			for i, u := range users {
				um, ok := u.(map[string]any)
				if !ok {
					continue
				}
				pw, _ := um["password"].(string)
				h, _ := um["hash"].(string)
				if pw != "" && h == "" {
					hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
					if err != nil {
						return "", errors.New("hash password failed")
					}
					um["hash"] = string(hash)
				}
				delete(um, "password") // never persist / forward cleartext
				users[i] = um
			}
			ba["users"] = users
		}
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// --- helpers ----------------------------------------------------------------

func (s *Server) requireWriter(w http.ResponseWriter) bool {
	if s.cfg.Writer == nil {
		writeNotSupported(w)
		return false
	}
	return true
}

// checkLocalToken validates the X-Local-Token header (or ?local_token query for
// EventSource). Same contract as statusapi.requireLocalToken.
func checkLocalToken(w http.ResponseWriter, r *http.Request) bool {
	got := r.Header.Get("X-Local-Token")
	if got == "" {
		got = r.URL.Query().Get("local_token")
	}
	if !creds.CompareLocalToken(got) {
		writeError(w, http.StatusUnauthorized, "local-token mismatch (fetch /v1/local-token)")
		return false
	}
	return true
}

func writeWriterErr(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrTunnelNotFound) {
		writeError(w, http.StatusNotFound, "no such tunnel")
		return
	}
	writeError(w, http.StatusBadRequest, err.Error())
}

// notSupported is the response for platform-only / unsupported endpoints (login,
// org/region switch, config import, replay). 501 says "this build can't do
// that" rather than "you're not allowed".
func notSupported(w http.ResponseWriter, _ *http.Request) {
	writeNotSupported(w)
}

func writeNotSupported(w http.ResponseWriter) {
	writeError(w, http.StatusNotImplemented,
		"this operation is not supported in self-hosted (standalone) mode")
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
