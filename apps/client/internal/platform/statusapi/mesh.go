package statusapi

// Connect (WireGuard mesh) status for the PLATFORM daemon's :7400 console.
//
// The local/standalone daemon serves /v1/mesh from internal/localweb (a `mesh:`
// YAML block drives it). The platform daemon has no such block — it AUTO-ENROLLS
// from the control plane (see cmd/calabi/daemon_mesh_platform.go) and reports the
// resulting node state here, so the SAME embedded SPA (internal/status/ui) renders
// Connect on both daemon kinds. Management (disable a node, ACL) stays in the web
// console (MESH.8b/8e); this surface is read-only status plus a local pause.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"runtime"
	"strings"

	"github.com/calabi/calabi/apps/client/internal/creds"
)

// MeshStatusSource is the platform daemon's live Connect state. The mesh
// enrollment controller implements it; nil = this daemon has no mesh subsystem
// wired (the endpoint 404s → the SPA shows "unavailable on this daemon").
type MeshStatusSource interface {
	// MeshStatus is the node's current Connect state. Enabled=false with
	// Paused=false means the org isn't enrolled (not entitled, or the platform
	// hasn't configured a coordinator) — the handler renders that as
	// 404/"unavailable". Paused=true means the operator stopped mesh locally
	// (MeshDown) — the handler returns it 200 so the SPA can offer a Start.
	MeshStatus() MeshStatus
	// MeshDown pauses local mesh participation (leaves the meshnet, stops
	// re-enrolling). Reversible via MeshUp. Idempotent. The org-wide kill switch
	// is the web console's node-disable (MESH.8b).
	MeshDown() error
	// MeshUp resumes local mesh participation after a MeshDown: it clears the
	// pause and re-enrolls immediately (no wait for the next poll). Idempotent.
	MeshUp() error
	// Advertise reports this node's current subnet-router / exit-node role.
	Advertise() MeshAdvertise
	// MeshServices reports what this machine DECLARES it offers: entries from
	// the config/flag (marked FromConfig) plus any added from this console.
	MeshServices() []MeshServiceDecl
	// SetMeshServices replaces the CONSOLE-managed declarations and restarts
	// the session so the new set is re-declared. Config-sourced entries are
	// untouched — the file is their source of truth.
	SetMeshServices([]MeshServiceDecl) error
	// SetAdvertise updates the role (routes / exit-node) and restarts the mesh
	// session so the change takes effect. The caller persists it to creds first.
	SetAdvertise(MeshAdvertise) error
}

// MeshAdvertise is this node's subnet-router / exit-node role — the editable part
// of the Connect page. Routes are the CIDRs it advertises as a subnet router;
// ExitNode advertises it AS an exit node; ExitPeer routes THIS node's default
// traffic through the named exit peer.
type MeshAdvertise struct {
	Routes   []string `json:"routes"`
	ExitNode bool     `json:"advertise_exit_node"`
	ExitPeer string   `json:"exit_node"`
	// --- the CONSUMER side: what this node accepts FROM peers ---
	//
	// AcceptRoutes is a POINTER so an omitted field means "leave unchanged". The
	// old console posts only the three fields above; without the pointer, every
	// save from an un-upgraded page would silently switch acceptance off.
	AcceptRoutes  *bool    `json:"accept_routes,omitempty"`
	RouteExcludes []string `json:"route_excludes,omitempty"`
}

// MeshServiceDecl is one service this machine declares on the mesh.
//
// FromConfig marks entries that came from --mesh-service / the config file: the
// console shows them but cannot remove them, because the file would re-declare
// them at the next restart anyway. There is deliberately no "approved" field —
// the daemon knows what it CLAIMED, not what an admin decided; that decision
// lives in the web console.
type MeshServiceDecl struct {
	Name  string `json:"name"`
	Proto string `json:"proto"`
	Port  int    `json:"port"`
	// Target is what THIS machine dials to reach the application, e.g.
	// "127.0.0.1:5432" or a box on its LAN. Empty means 127.0.0.1:<port>.
	// Opening Port in the packet filter does nothing if the app is bound to
	// loopback only, which is why the two are separate.
	Target     string `json:"target,omitempty"`
	Note       string `json:"note,omitempty"`
	FromConfig bool   `json:"from_config,omitempty"`
	// FromConsole marks a service a manager registered in the WEB console. This
	// machine learns of it from the netmap and self-checks it like any other,
	// but it is not this machine's to edit or remove — the console owns it, and
	// persisting it here would create a second row claiming the same name.
	FromConsole bool `json:"from_console,omitempty"`
	// The machine's own last self-check (F3b). Checked=false means it could not
	// test — a udp service, or no observation yet — which is NOT a failure, and
	// the UI must not render it as one.
	//
	// TargetOK && !MeshOK is the case worth having a local view for at all: the
	// app answers where this machine dials it but not on the address peers use,
	// i.e. it is bound to 127.0.0.1. The person who can fix that is standing at
	// this machine.
	Checked  bool `json:"checked,omitempty"`
	TargetOK bool `json:"target_ok,omitempty"`
	MeshOK   bool `json:"mesh_ok,omitempty"`
}

// MeshStatus is the JSON shape for GET /v1/mesh. Mirrors localweb.MeshStatus
// field-for-field (plus Paused) so one SPA type (api/types.ts MeshStatus) serves
// both daemons.
type MeshStatus struct {
	Enabled bool   `json:"enabled"`
	Up      bool   `json:"up"`
	Paused  bool   `json:"paused,omitempty"` // stopped locally via MeshDown; Start re-enrolls
	Coord   string `json:"coord,omitempty"`
	Relay   string `json:"relay,omitempty"`
	// DerpHome is the region code this node is homed on ("self-…" = the org's own
	// relay); Relay is the address. Lets the overview flag "中继节点：自建".
	DerpHome string `json:"derp_home,omitempty"`
	Name     string `json:"name,omitempty"`
	Overlay  string `json:"overlay,omitempty"`
	// OrgID is the org (== meshnet) the RUNNING session enrolled into — not the
	// org the daemon is currently authenticated as. They differ for the moment
	// between an org switch and the re-enrollment, which is exactly when the
	// operator most needs to see it.
	OrgID int64      `json:"org_id,omitempty"`
	Peers []MeshPeer `json:"peers"`
}

// MeshPeer is one peer's live WireGuard state.
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

// handleMesh serves GET /v1/mesh. Read-only (loopback bind = trust boundary).
func (s *Server) handleMesh(w http.ResponseWriter, _ *http.Request) {
	if s.cfg.Mesh == nil {
		writeError(w, http.StatusNotFound, "mesh not available on this daemon")
		return
	}
	st := s.cfg.Mesh.MeshStatus()
	if !st.Enabled && !st.Paused {
		// Not enrolled AND not locally paused: the org isn't entitled, or the
		// platform hasn't wired a coordinator. Report "unavailable" (404) instead
		// of the local-daemon "add a mesh: block" hint, which doesn't apply here.
		// A locally-paused node returns 200 (below) so the SPA can offer Start.
		writeError(w, http.StatusNotFound, "mesh not enabled for this daemon")
		return
	}
	if st.Peers == nil {
		st.Peers = []MeshPeer{}
	}
	writeJSON(w, http.StatusOK, st)
}

// handleMeshDown serves POST /v1/mesh/down (local-token gated in Register): pause
// this node's mesh participation. Reversible with POST /v1/mesh/up.
func (s *Server) handleMeshDown(w http.ResponseWriter, _ *http.Request) {
	if s.cfg.Mesh == nil {
		writeError(w, http.StatusNotFound, "mesh not available on this daemon")
		return
	}
	if err := s.cfg.Mesh.MeshDown(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "down"})
}

// handleMeshUp serves POST /v1/mesh/up (local-token gated): resume mesh after a
// MeshDown — clear the pause and re-enroll immediately.
func (s *Server) handleMeshUp(w http.ResponseWriter, _ *http.Request) {
	if s.cfg.Mesh == nil {
		writeError(w, http.StatusNotFound, "mesh not available on this daemon")
		return
	}
	if err := s.cfg.Mesh.MeshUp(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "up"})
}

// handleMeshAdvertiseGet serves GET /v1/mesh/advertise: the node's current
// subnet-router / exit-node role, plus forwarding_supported (true only on Linux,
// where the daemon can actually forward — elsewhere it advertises but doesn't).
func (s *Server) handleMeshAdvertiseGet(w http.ResponseWriter, _ *http.Request) {
	if s.cfg.Mesh == nil {
		writeError(w, http.StatusNotFound, "mesh not available on this daemon")
		return
	}
	adv := s.cfg.Mesh.Advertise()
	if adv.Routes == nil {
		adv.Routes = []string{}
	}
	// The consumer side lives in creds, not in the advertise state: it is this
	// machine's own stance, not something it announces to the meshnet.
	accept, excludes := false, []string{}
	if c, err := creds.Load(); err == nil && c != nil {
		if c.MeshAcceptRoutes != nil {
			accept = *c.MeshAcceptRoutes
		}
		if c.MeshRouteExcludes != nil {
			excludes = c.MeshRouteExcludes
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"routes":               adv.Routes,
		"advertise_exit_node":  adv.ExitNode,
		"exit_node":            adv.ExitPeer,
		"forwarding_supported": runtime.GOOS == "linux",
		"accept_routes":        accept,
		"route_excludes":       excludes,
	})
}

// handleMeshAdvertiseSet serves POST /v1/mesh/advertise (local-token gated): set
// the node's subnet-router / exit-node role. It validates the CIDRs, persists to
// creds (so the choice survives a restart), then restarts the mesh session so the
// new advertisement takes effect. NOT agent-blocked — this is data-plane routing
// config, like edge-region, not identity.
func (s *Server) handleMeshAdvertiseSet(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Mesh == nil {
		writeError(w, http.StatusNotFound, "mesh not available on this daemon")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 16*1024))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	var in MeshAdvertise
	if err := json.Unmarshal(body, &in); err != nil {
		writeError(w, http.StatusBadRequest, "parse: "+err.Error())
		return
	}
	// Normalize + validate the CIDRs (masked to their network); reject garbage so
	// a typo surfaces here, not as a silent no-op at enroll time.
	routes := make([]string, 0, len(in.Routes))
	for _, raw := range in.Routes {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		p, perr := netip.ParsePrefix(raw)
		if perr != nil {
			writeError(w, http.StatusBadRequest, "invalid route "+raw+": "+perr.Error())
			return
		}
		routes = append(routes, p.Masked().String())
	}
	adv := MeshAdvertise{Routes: routes, ExitNode: in.ExitNode, ExitPeer: strings.TrimSpace(in.ExitPeer)}

	// Persist to creds so the role survives a daemon restart.
	cfg, _ := creds.Load()
	if cfg == nil {
		cfg = &creds.Config{}
	}
	cfg.MeshAdvertiseRoutes = routes
	cfg.MeshAdvertiseExitNode = adv.ExitNode
	cfg.MeshExitNode = adv.ExitPeer
	// Consumer side. Both are "leave unchanged" when omitted, so a save from a
	// page that predates these fields can't flip them.
	if in.AcceptRoutes != nil {
		v := *in.AcceptRoutes
		cfg.MeshAcceptRoutes = &v
	}
	if in.RouteExcludes != nil {
		excludes := make([]string, 0, len(in.RouteExcludes))
		for _, raw := range in.RouteExcludes {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			p, perr := netip.ParsePrefix(raw)
			if perr != nil {
				writeError(w, http.StatusBadRequest, "invalid excluded route "+raw+": "+perr.Error())
				return
			}
			excludes = append(excludes, p.Masked().String())
		}
		cfg.MeshRouteExcludes = excludes
	}
	if err := creds.Save(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "persist: "+err.Error())
		return
	}
	if err := s.cfg.Mesh.SetAdvertise(adv); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.logger.Info("mesh advertise updated", "routes", routes, "exit_node", adv.ExitNode, "exit_peer", adv.ExitPeer,
		"accept_routes", cfg.MeshAcceptRoutes, "route_excludes", cfg.MeshRouteExcludes)
	acceptOut := false
	if cfg.MeshAcceptRoutes != nil {
		acceptOut = *cfg.MeshAcceptRoutes
	}
	excludesOut := cfg.MeshRouteExcludes
	if excludesOut == nil {
		excludesOut = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"routes":               routes,
		"advertise_exit_node":  adv.ExitNode,
		"exit_node":            adv.ExitPeer,
		"forwarding_supported": runtime.GOOS == "linux",
		"accept_routes":        acceptOut,
		"route_excludes":       excludesOut,
	})
}
