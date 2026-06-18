// Package status powers the local-only HTTP status surface the calabi
// client serves on :7400.
//
// It is the source of truth for runtime state the user might want to inspect
// without parsing logs:
//
//   - which tunnels are registered and what they're pointing at,
//   - bytes pumped through each direction,
//   - connection state to the edge node.
//
// The server intentionally binds to 127.0.0.1 (and the listen address can be
// overridden via CALABI_STATUS_ADDR for tests). No auth -- it's local only.
package status

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// desktopUAMarker is the substring we look for in the User-Agent
// header to identify a request coming from the Tauri desktop shell
// (or another caller deliberately impersonating it). The Tauri
// window config sets a UA that ends in "CalabiDesktop/<version>"
// so we match on the literal "CalabiDesktop" prefix.
const desktopUAMarker = "CalabiDesktop"

// TunnelInfo is a snapshot of a registered tunnel as the user sees it.
//
// Pending=true marks an entry that arrived via Phase C's server→client
// CONFIG_PUSH(upsert_proxies) but hasn't been activated yet (no live
// NEW_PROXY round-trip on the client side). The status UI displays
// these with an "等待客户端启动" tag — the user still needs to run
// `calabi http <port>` etc. for the matching local upstream before
// traffic can flow. Once the user does that, the proxy lifecycle
// flips Pending to false via the normal AddTunnel path.
type TunnelInfo struct {
	ProxyID     string `json:"proxy_id"`
	Name        string `json:"name"`
	Type        string `json:"type"`        // "http" | "tcp" | ...
	LocalAddr   string `json:"local_addr"`  // "127.0.0.1:9090"
	PublicAddr  string `json:"public_addr"` // domain or tcp://host:port
	BytesIn     int64  `json:"bytes_in"`    // visitor -> local
	BytesOut    int64  `json:"bytes_out"`   // local -> visitor
	Connections int64  `json:"connections"` // cumulative
	Pending     bool   `json:"pending,omitempty"`
	TunnelID    int64  `json:"tunnel_id,omitempty"`
}

// Lifecycle is the daemon's coarse-grained state machine surfaced via
// /healthz. Finer state (per-tunnel) is in Snapshot.Tunnels. The order
// of values matters: the SPA badge picks a color via numeric range.
type Lifecycle int

const (
	LifecycleStarting Lifecycle = iota
	LifecycleConnecting
	LifecycleConnected
	LifecycleReconnecting
	LifecycleStopped
	LifecycleFatal
	// LifecycleUnavailable — the reconnect loop tried maxReconnectFails
	// times without establishing a session and has PARKED: it stops
	// retrying until the user takes an action (manual region switch /
	// re-login / org switch). Surfaced to the SPA as "服务器不可用，可手动
	// 切换地域". Appended last so existing wire values + the `l !=
	// LifecycleFatal` comparisons elsewhere stay stable.
	LifecycleUnavailable
)

// String returns the wire form used in /healthz JSON. Stable contract —
// the SPA matches on these literals.
func (l Lifecycle) String() string {
	switch l {
	case LifecycleStarting:
		return "starting"
	case LifecycleConnecting:
		return "connecting"
	case LifecycleConnected:
		return "connected"
	case LifecycleReconnecting:
		return "reconnecting"
	case LifecycleStopped:
		return "stopped"
	case LifecycleFatal:
		return "fatal"
	case LifecycleUnavailable:
		return "unavailable"
	}
	return "unknown"
}

// EdgeSwitchInfo is the daemon's "your sticky edge was unavailable so
// we landed on a different one" alert. SPA renders it as a yellow
// banner above the tunnel table — see Tunnels.tsx. nil = no switch
// happened (the normal case).
//
// previous_edge_node_id is what creds.LastEdgeNodeID held before this
// boot; current_edge_node_id is what daemon dialled this time. The
// SPA shows both so the user knows which edge to wait on for recovery.
type EdgeSwitchInfo struct {
	PreviousEdgeNodeID int64     `json:"previous_edge_node_id"`
	CurrentEdgeNodeID  int64     `json:"current_edge_node_id"`
	Since              time.Time `json:"since"`
}

// Snapshot is everything the / and /tunnels endpoints render.
type Snapshot struct {
	ClientVersion string `json:"client_version"`
	ServerAddr    string `json:"server_addr"`
	SessionID     string `json:"session_id,omitempty"`
	TenantID      string `json:"tenant_id,omitempty"`
	ClientID      string `json:"client_id,omitempty"`
	// edge's HTTPListener.BaseDomain delivered in AUTH_RESP. Used as a
	// last-resort host for TCP/UDP public addrs when neither server_addr
	// nor server_ip is available. Empty on old edges.
	BaseDomain string `json:"base_domain,omitempty"`
	// dotted-decimal IP the daemon's underlying TCP/TLS conn is talking to
	// (the edge's resolved address). FALLBACK host for the TCP/UDP public
	// addr — the SPA now prefers server_addr's hostname (FQDN) over this,
	// flipped 2026-06 per operator request so the public addr is a stable
	// hostname (e.g. edge01-va.calabi.net) rather than a bare IP that
	// changes when the edge moves. Empty when not yet authenticated.
	ServerIP string `json:"server_ip,omitempty"`
	// HTTPPort / HTTPSPort are the edge's public HTTP / HTTPS listener ports
	// (AUTH_RESP). A self-hosted console renders `http://<domain>:<http_port>`
	// for non-standard ports; 0 = unknown (platform edge on 80/443) → bare domain.
	HTTPPort  uint32 `json:"http_port,omitempty"`
	HTTPSPort uint32 `json:"https_port,omitempty"`
	// EdgeNodeID is the identity-svc edge_node_id of the edge this
	// daemon picked + dialed this boot (from edgepicker.Pick). SPA's
	// Tunnels page compares each row's edge_node_id against this so it
	// can tag tunnels as 「当前节点」vs「其他节点」. 0 when the dial
	// path hit a tier (CALABI_SERVER env / compile-time default) that
	// didn't go through /v1/edges and couldn't resolve an id.
	EdgeNodeID int64 `json:"edge_node_id,omitempty"`
	// ActiveOrgID is the org the daemon's saved token is scoped to
	// (creds.ActiveOrgID — updated on login / org-switch). The SPA's
	// top-bar Org chip derives the active Org from THIS, not from a
	// network-fetched /v1/orgs (which the SPA caches for 60s and only
	// force-refreshes on a full reload). Snapshot is polled every few
	// seconds and is a free local read, so the chip tracks the token
	// within one poll even if a switch's reload is skipped — keeping the
	// displayed Org and the (token-scoped) tunnel list from diverging.
	// 0 = unknown (pre-login / never switched); SPA falls back to /v1/orgs.
	ActiveOrgID int64 `json:"active_org_id,omitempty"`
	// PreferredRegion is the region the daemon is anchored to (CLI flag /
	// creds.EdgeRegion / last successful region). The SPA's top-bar region
	// switcher highlights this even when the daemon is disconnected /
	// parked (LifecycleUnavailable) and there's no live edge_node_id to
	// derive a region from. Empty on a brand-new install before the first
	// successful connect anchors a region.
	PreferredRegion string       `json:"preferred_region,omitempty"`
	Connected       bool         `json:"connected"`
	Lifecycle       string       `json:"lifecycle"`
	StartedAt       time.Time    `json:"started_at"`
	UptimeSeconds   int64        `json:"uptime_seconds"`
	Tunnels         []TunnelInfo `json:"tunnels"`
	// EdgeSwitch surfaces the sticky-edge fallback warning when
	// edgepicker had to land on a different edge than the previous
	// boot. nil = no switch this run (the typical case).
	EdgeSwitch *EdgeSwitchInfo `json:"edge_switch,omitempty"`
}

// State is the mutable runtime state shared by the client's tunnel
// goroutines and the status HTTP handlers.
type State struct {
	mu              sync.RWMutex
	tunnels         map[string]*TunnelInfo // keyed by proxy_id
	connected       atomic.Bool
	lifecycle       atomic.Int32 // Lifecycle cast to int32
	sessionID       string
	tenantID        string
	clientID        string
	baseDomain      string // edge BaseDomain from AUTH_RESP
	serverIP        string // resolved IP of the edge connection
	httpPort        uint32 // edge public HTTP listener port (AUTH_RESP); 0 = unknown
	httpsPort       uint32 // edge public HTTPS listener port (AUTH_RESP); 0 = unknown
	edgeNodeID      int64  // current edge id picked by edgepicker; 0 = unknown (tier 1/4 fallback)
	activeOrgID     int64  // org the saved token is scoped to (creds.ActiveOrgID); 0 = unknown
	preferredRegion string // region the daemon is anchored to (for the SPA region switcher)
	startedAt       time.Time
	lifecycleAt     time.Time
	version         string
	serverAddr      string
	edgeSwitch      *EdgeSwitchInfo // sticky-edge fallback alert; nil when no switch

	// metrics
	registry   *prometheus.Registry
	mActive    prometheus.Gauge
	mConns     *prometheus.CounterVec
	mBytes     *prometheus.CounterVec
	mConnected prometheus.Gauge
	mBuildInfo *prometheus.GaugeVec
}

// New constructs an empty State.
func New(version, serverAddr string) *State {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	s := &State{
		tunnels:    make(map[string]*TunnelInfo),
		startedAt:  time.Now(),
		version:    version,
		serverAddr: serverAddr,
		registry:   reg,
	}
	s.mActive = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "calabi_client_active_tunnels",
		Help: "Number of tunnels currently registered with the edge node.",
	})
	s.mConns = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "calabi_client_visitor_connections_total",
		Help: "Total visitor connections handled, by tunnel type.",
	}, []string{"proxy_type"})
	s.mBytes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "calabi_client_bytes_transferred_total",
		Help: "Bytes piped through tunnels, by type and direction.",
	}, []string{"proxy_type", "direction"})
	s.mConnected = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "calabi_client_session_connected",
		Help: "1 if the client has an authenticated session to the edge node, else 0.",
	})
	s.mBuildInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "calabi_client_build_info",
		Help: "Constant 1 with build-tag labels for dashboard joins.",
	}, []string{"version", "go_version", "vcs_revision"})
	reg.MustRegister(s.mActive, s.mConns, s.mBytes, s.mConnected, s.mBuildInfo)

	gov, rev := readBuildInfo()
	s.mBuildInfo.WithLabelValues(version, gov, rev).Set(1)
	return s
}

// SetConnected toggles the connection state (true after AUTH_RESP).
// baseDomain is the edge's HTTPListener.BaseDomain, used to render TCP/UDP
// public addresses on the SPA. Empty when the edge is too old to advertise
// it (the SPA falls back to snap.server_addr's host in that case).
// serverIP is the resolved IP of the edge's TCP/TLS connection (from the
// mux's RemoteAddr) — preferred by the SPA for IP:port display.
func (s *State) SetConnected(connected bool, sessionID, tenantID, clientID, baseDomain, serverIP string, httpPort, httpsPort uint32) {
	s.mu.Lock()
	s.sessionID = sessionID
	s.tenantID = tenantID
	s.clientID = clientID
	s.baseDomain = baseDomain
	s.serverIP = serverIP
	s.httpPort = httpPort
	s.httpsPort = httpsPort
	s.mu.Unlock()
	s.connected.Store(connected)
	if connected {
		s.mConnected.Set(1)
		s.SetLifecycle(LifecycleConnected)
	} else {
		s.mConnected.Set(0)
		// Don't override Fatal / Stopped / Unavailable — those are
		// terminal / parked states the reconnect loop owns.
		l := Lifecycle(s.lifecycle.Load())
		if l != LifecycleFatal && l != LifecycleStopped && l != LifecycleUnavailable {
			s.SetLifecycle(LifecycleReconnecting)
		}
	}
}

// SetServer updates the displayed dial address.
// Lock-protected because the snapshot reader takes mu.
func (s *State) SetServer(addr string) {
	if addr == "" {
		return
	}
	s.mu.Lock()
	s.serverAddr = addr
	s.mu.Unlock()
}

// SetEdgeNodeID stores the edge_node_id this daemon picked + dialed
// this boot. Called once from the daemon right after edgepicker.Pick.
// 0 = unknown (the env-override / compile-time-default tiers don't
// have an id to give us); the SPA shows tunnels as 「未知节点」 in
// that case rather than the false-positive 「其他节点」we'd render
// if we left the field zero AND compared by equality.
func (s *State) SetEdgeNodeID(id int64) {
	s.mu.Lock()
	s.edgeNodeID = id
	s.mu.Unlock()
}

// SetActiveOrgID records the org the daemon's saved token is scoped to
// (creds.ActiveOrgID). Called from the daemon at session bind + on the
// login / org-switch / logout hooks so the SPA's top-bar Org chip tracks
// the token within one snapshot poll, instead of the SPA's 60s-cached
// /v1/orgs which only force-refreshes on a full page reload. 0 = unknown.
func (s *State) SetActiveOrgID(id int64) {
	s.mu.Lock()
	s.activeOrgID = id
	s.mu.Unlock()
}

// SetPreferredRegion records the region the daemon is anchored to (the
// effective region edgepicker is locked to). Called from the daemon each
// reconnect so the SPA region switcher can highlight it even while the
// daemon is parked / disconnected and there's no live edge to derive a
// region from. Empty string is allowed (brand-new install, no anchor yet).
func (s *State) SetPreferredRegion(region string) {
	s.mu.Lock()
	s.preferredRegion = region
	s.mu.Unlock()
}

// SetEdgeSwitched records that this daemon boot picked a different edge
// than its previous run. SPA reads it via Snapshot.EdgeSwitch and shows
// a banner telling the user their tunnels bound to the previous edge
// are temporarily unreachable.
//
// The alert stays sticky across reconnect attempts within this daemon
// process — only ClearEdgeSwitch (called by SPA after the user reads /
// dismisses the banner) or the user explicitly switching back to the
// previous edge clears it. Subsequent successful Picks that land on
// the SAME new edge don't re-fire the alert.
func (s *State) SetEdgeSwitched(previousID, currentID int64) {
	if currentID == 0 || previousID == 0 || previousID == currentID {
		return
	}
	now := time.Now()
	s.mu.Lock()
	s.edgeSwitch = &EdgeSwitchInfo{
		PreviousEdgeNodeID: previousID,
		CurrentEdgeNodeID:  currentID,
		Since:              now,
	}
	s.mu.Unlock()
}

// ClearEdgeSwitch dismisses the banner. The SPA calls this after
// rendering the alert OR when the daemon's next successful dial lands
// back on the previous edge (recovery). Idempotent.
func (s *State) ClearEdgeSwitch() {
	s.mu.Lock()
	s.edgeSwitch = nil
	s.mu.Unlock()
}

// SetLifecycle stores the daemon's coarse state machine for /healthz.
// Atomic store keeps the path lock-free; lifecycleAt is the timestamp
// of the last transition (under mu).
func (s *State) SetLifecycle(l Lifecycle) {
	s.lifecycle.Store(int32(l))
	s.mu.Lock()
	s.lifecycleAt = time.Now()
	s.mu.Unlock()
}

// LifecycleNow returns the current lifecycle value. Reader-side helper.
func (s *State) LifecycleNow() Lifecycle {
	return Lifecycle(s.lifecycle.Load())
}

// AddTunnel records a successful NEW_PROXY registration.
func (s *State) AddTunnel(t TunnelInfo) {
	s.mu.Lock()
	tt := t // copy
	s.tunnels[t.ProxyID] = &tt
	n := len(s.tunnels)
	s.mu.Unlock()
	s.mActive.Set(float64(n))
}

// AddActiveTunnel is the StatusTracker-interface counterpart of AddTunnel.
//
// It exists so the session package can register a daemon-mode auto-
// claimed tunnel without importing internal/status (which would also
// drag in the prometheus deps from the session pkg). The single-tunnel
// CLIs (calabi http/tcp/udp/sni) call AddTunnel directly with the
// PublicAddr formatted to their type; daemon-mode auto-claim has only
// the bare Tunnel info, so we synthesize PublicAddr here from (kind,
// localAddr, publicAddr) — caller is expected to pass an already-built
// publicAddr, but we tolerate empty (used by SPA only for Overview's
// metadata column, falls back to bff-console's domain/remote_port for
// the actual cell).
//
// If a row already exists for this proxy_id (e.g. UpsertPending was
// promoted), the byte/connection counters are preserved so the user
// doesn't see counters bounce back to 0 on re-claim.
func (s *State) AddActiveTunnel(proxyID string, tunnelID int64, name, kind, localAddr, publicAddr string) {
	s.mu.Lock()
	var bytesIn, bytesOut, conns int64
	if existing, ok := s.tunnels[proxyID]; ok {
		bytesIn, bytesOut, conns = existing.BytesIn, existing.BytesOut, existing.Connections
	}
	t := TunnelInfo{
		ProxyID:     proxyID,
		TunnelID:    tunnelID,
		Name:        name,
		Type:        kind,
		LocalAddr:   localAddr,
		PublicAddr:  publicAddr,
		BytesIn:     bytesIn,
		BytesOut:    bytesOut,
		Connections: conns,
	}
	s.tunnels[proxyID] = &t
	n := len(s.tunnels)
	s.mu.Unlock()
	s.mActive.Set(float64(n))
}

// RemoveActiveTunnel is the StatusTracker-interface counterpart of
// RemoveTunnel — see AddActiveTunnel for the rationale.
func (s *State) RemoveActiveTunnel(proxyID string) {
	s.RemoveTunnel(proxyID)
}

// RemoveTunnel forgets a tunnel after CLOSE_PROXY or disconnect.
func (s *State) RemoveTunnel(proxyID string) {
	s.mu.Lock()
	delete(s.tunnels, proxyID)
	n := len(s.tunnels)
	s.mu.Unlock()
	s.mActive.Set(float64(n))
}

// ClearAllTunnels wipes the entire active+pending tunnel set. Reserved
// for events that invalidate the caller's prior view of the world —
// notably SPA login (a different user logs in on this machine) and
// active-Org switch (the data plane is Org-scoped; the previous Org's
// claims do not carry over). Network blips deliberately don't call
// this — the existing rows stay visible so the user sees "reconnecting,
// your tunnels are still here" rather than a transient empty list.
//
// After this call the daemon's `/tunnels` snapshot is empty until the
// reconnected session's catch-up CONFIG_PUSH repopulates it with the
// freshly-claimed set.
func (s *State) ClearAllTunnels() {
	s.mu.Lock()
	s.tunnels = make(map[string]*TunnelInfo)
	s.mu.Unlock()
	s.mActive.Set(0)
}

// UpsertPending records a server-pushed tunnel that the user hasn't
// activated locally yet (Phase C). Keyed by tunnel_id since the
// console-created tunnel has no proxy_id until the client actually
// runs `calabi http ...` and goes through the live NEW_PROXY flow.
func (s *State) UpsertPending(tunnelID int64, name, kind, localAddr, domain string, remotePort uint32) {
	key := "pending:" + itoaInt64(tunnelID)
	pub := domain
	if pub == "" && remotePort != 0 {
		pub = ":" + itoaInt64(int64(remotePort))
	}
	t := TunnelInfo{
		ProxyID:    key,
		TunnelID:   tunnelID,
		Name:       name,
		Type:       kind,
		LocalAddr:  localAddr,
		PublicAddr: pub,
		Pending:    true,
	}
	s.mu.Lock()
	existing, ok := s.tunnels[key]
	if ok {
		// Preserve byte counters / conn counts if we somehow already had it.
		t.BytesIn = existing.BytesIn
		t.BytesOut = existing.BytesOut
		t.Connections = existing.Connections
	}
	tt := t
	s.tunnels[key] = &tt
	n := len(s.tunnels)
	s.mu.Unlock()
	s.mActive.Set(float64(n))
}

// RemovePendingByTunnelID removes a server-pushed pending entry by its
// tunnel_id. Used when the edge tells us the upstream tunnel was deleted.
func (s *State) RemovePendingByTunnelID(tunnelID int64) {
	key := "pending:" + itoaInt64(tunnelID)
	s.mu.Lock()
	delete(s.tunnels, key)
	n := len(s.tunnels)
	s.mu.Unlock()
	s.mActive.Set(float64(n))
}

// ReconcileToTunnelIDs drops any tunnel entry — active or pending —
// whose tunnel_id is not in the `keep` set, and returns the proxy_ids
// of the active rows that were dropped so the caller can also unwind
// the proxy registry / send CLOSE_PROXY.
//
// Used by the FullSync path on a catch-up CONFIG_PUSH: the edge tells
// the client the authoritative list of tunnels it owns; the client
// prunes anything stale (e.g., a console-side delete the daemon missed
// while briefly disconnected). Without this the "活跃隧道" count
// inflates over time as orphan rows accumulate.
//
// keep with tunnel_id=0 is intentionally ignored — those are CLI-launched
// single-tunnel rows the daemon's auto-claim path didn't touch and
// shouldn't reconcile away.
func (s *State) ReconcileToTunnelIDs(keep map[int64]struct{}) (droppedActiveProxyIDs []string) {
	s.mu.Lock()
	for proxyID, t := range s.tunnels {
		if t.TunnelID == 0 {
			continue
		}
		if _, ok := keep[t.TunnelID]; ok {
			continue
		}
		delete(s.tunnels, proxyID)
		if !t.Pending {
			droppedActiveProxyIDs = append(droppedActiveProxyIDs, proxyID)
		}
	}
	n := len(s.tunnels)
	s.mu.Unlock()
	s.mActive.Set(float64(n))
	return droppedActiveProxyIDs
}

func itoaInt64(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [21]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// AddBytes increments byte counters on the matching tunnel.
//
// direction is "in" for visitor->local, "out" for local->visitor.
func (s *State) AddBytes(proxyID, direction string, n int64) {
	if n <= 0 {
		return
	}
	s.mu.Lock()
	t, ok := s.tunnels[proxyID]
	if ok {
		switch direction {
		case "in":
			t.BytesIn += n
		case "out":
			t.BytesOut += n
		}
	}
	proxyType := ""
	if ok {
		proxyType = t.Type
	}
	s.mu.Unlock()
	if proxyType != "" {
		dirLabel := "visitor_to_local"
		if direction == "out" {
			dirLabel = "local_to_visitor"
		}
		s.mBytes.WithLabelValues(proxyType, dirLabel).Add(float64(n))
	}
}

// AddConnection bumps the per-tunnel connection counter.
func (s *State) AddConnection(proxyID string) {
	s.mu.Lock()
	t, ok := s.tunnels[proxyID]
	if ok {
		t.Connections++
	}
	proxyType := ""
	if ok {
		proxyType = t.Type
	}
	s.mu.Unlock()
	if proxyType != "" {
		s.mConns.WithLabelValues(proxyType).Inc()
	}
}

// SnapshotNow renders the current state without locking the writers.
//
// Tunnels is explicitly initialized to a non-nil empty slice so the
// JSON wire shape is "tunnels": [] (not "tunnels": null) when no
// tunnels are registered yet. The SPA assumes tunnels is iterable
// and crashes on.reduce()/.forEach() of null — costs a wasted alloc
// per snapshot to save the SPA an `?? []` everywhere.
func (s *State) SnapshotNow() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := Snapshot{
		ClientVersion:   s.version,
		ServerAddr:      s.serverAddr,
		SessionID:       s.sessionID,
		TenantID:        s.tenantID,
		ClientID:        s.clientID,
		BaseDomain:      s.baseDomain,
		ServerIP:        s.serverIP,
		HTTPPort:        s.httpPort,
		HTTPSPort:       s.httpsPort,
		EdgeNodeID:      s.edgeNodeID,
		ActiveOrgID:     s.activeOrgID,
		PreferredRegion: s.preferredRegion,
		Connected:       s.connected.Load(),
		Lifecycle:       Lifecycle(s.lifecycle.Load()).String(),
		StartedAt:       s.startedAt,
		UptimeSeconds:   int64(time.Since(s.startedAt).Seconds()),
		Tunnels:         []TunnelInfo{},
	}
	if s.edgeSwitch != nil {
		es := *s.edgeSwitch
		out.EdgeSwitch = &es
	}
	for _, t := range s.tunnels {
		out.Tunnels = append(out.Tunnels, *t)
	}
	return out
}

// Registry returns the underlying Prometheus registry (for promhttp.Handler).
func (s *State) Registry() *prometheus.Registry { return s.registry }

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------

// Server is the local status HTTP server.
type Server struct {
	state  *State
	logger *slog.Logger
	addr   string
	srv    *http.Server

	// apiRegister, when non-nil, gets called with the mux during Run()
	// so the api package can attach /v1/* handlers without status.go
	// importing api (which would cycle: api needs status types).
	apiRegister func(mux *http.ServeMux)

	// allowBrowser disables the desktop-UA browserGuard. Set by the LOCAL
	// (standalone) console, which is meant to be opened in a normal browser
	// (`calabi ui` / `calabi daemon --local`) rather than the Tauri shell. The
	// guard is anti-footgun, not security (the socket is loopback-only), so
	// relaxing it for self-hosters is safe. See AllowBrowser + browserGuard.
	allowBrowser bool
}

// NewServer constructs a Server bound to addr (default "127.0.0.1:7400").
func NewServer(logger *slog.Logger, state *State, addr string) *Server {
	if addr == "" {
		addr = "127.0.0.1:7400"
	}
	return &Server{
		logger: logger.With("component", "client.status"),
		state:  state,
		addr:   addr,
	}
}

// AttachAPI hooks a /v1/* registrar to be called when Run() builds the
// mux. The api package builds the registrar with its own dependencies
// (bff-console URL, creds loader, etc.) and hands it in from the daemon
// boot path.
func (s *Server) AttachAPI(register func(mux *http.ServeMux)) {
	s.apiRegister = register
}

// AllowBrowser disables the desktop-UA browserGuard so the page is reachable
// from a normal browser. Call before Run(). Used by the standalone local
// console (the self-hoster opens http://127.0.0.1:7400 in their browser; there
// is no Tauri shell to stamp the CalabiDesktop UA).
func (s *Server) AllowBrowser() {
	s.allowBrowser = true
}

// Run binds and serves until ctx is cancelled. Returns nil on graceful
// shutdown. A bind failure on the default :7400 (e.g. port already in
// use because two clients are running) is logged at WARN and returned as
// nil -- we never want the status page to take down the tunnel itself.
func (s *Server) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	// SPA at /ui/, root index at /. The SPA bundle (Vite
	// build with base="./") references its JS + CSS under /assets/*
	// when loaded from the root path. Without a /assets/ mount these
	// requests fall through to the "/" catch-all → 404, the browser
	// can't load the React bundle, the WebView paints blank. fixed by adding the /assets/ mount.
	//
	// The /ui/ mount is kept for back-compat (older callers may still
	// link to /ui/index.html).
	if spaFS, err := UIFileSystem(); err == nil {
		mux.Handle("/ui/", http.StripPrefix("/ui/", http.FileServer(http.FS(spaFS))))
		mux.Handle("/assets/", http.FileServer(http.FS(spaFS)))
	}
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/tunnels", s.handleTunnels)
	mux.Handle("/metrics", promhttp.HandlerFor(s.state.Registry(), promhttp.HandlerOpts{
		Registry: s.state.Registry(),
	}))
	// log tail + SSE stream surfaced for the writable UI.
	registerLogsRoutes(mux)
	// writable REST API + local-token middleware. The api
	// package self-registers under /v1/.
	if s.apiRegister != nil {
		s.apiRegister(mux)
	}

	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		s.logger.Warn("status page unavailable", "addr", s.addr, "err", err)
		// Block until ctx done so we don't crash the client.
		<-ctx.Done()
		return nil
	}
	var handler http.Handler = mux
	if !s.allowBrowser {
		handler = browserGuard(mux)
	}
	s.srv = &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	s.logger.Info("status page up", "url", "http://"+ln.Addr().String())

	errCh := make(chan error, 1)
	go func() {
		err := s.srv.Serve(ln)
		if err != nil && err != http.ErrServerClosed {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		return err
	}
}

// browserGuard rejects requests that don't carry the desktop-client
// User-Agent marker, so http://127.0.0.1:7400 isn't usable from a
// plain browser. The Tauri window sets a UA suffix of
// "CalabiDesktop/<version>" — anything else gets a 403 + a friendly
// HTML page telling the user to open the desktop client.
//
// /healthz and /metrics are always allowed: they're operator surfaces
// (terminal `curl /healthz`, Prometheus scrape) with no UI value, and
// gating them would silently break scripts for no security gain.
//
// This is anti-footgun, not security: anyone running curl with the
// matching -A header bypasses. Mutating endpoints under /v1/* are
// still gated by the local-token middleware.
func browserGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}
		if strings.Contains(r.Header.Get("User-Agent"), desktopUAMarker) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, blockedPage)
	})
}

const blockedPage = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Calabi · Desktop client only</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "PingFang SC", "Microsoft YaHei", sans-serif;
         display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0;
         background: #f5f7fa; color: #1f2937; }
  .card { background: white; padding: 2.5rem 3rem; border-radius: 12px;
          box-shadow: 0 4px 24px rgba(0,0,0,0.06);
          text-align: center; max-width: 480px; }
  h1 { margin: 0 0 0.75rem; font-size: 1.25rem; }
  p  { margin: 0.5rem 0; color: #6b7280; line-height: 1.6; font-size: 0.95rem; }
</style>
</head>
<body>
  <div class="card">
    <h1>Open this in the Calabi desktop client</h1>
    <p>The local dashboard is only accessible from the Calabi desktop client.</p>
    <p>If you have the client installed, launch Calabi; otherwise download it from the website.</p>
  </div>
</body>
</html>
`

// handleHealthz serves the structured /healthz used by the SPA banner
// and the Tauri loading shell. Always HTTP 200 — the lifecycle
// state (including "fatal") is in the body; HTTP status only signals
// "is the local API alive at all".
//
// Why not 503 on Fatal: a Fatal daemon (auth rejected by edge) still
// has a working :7400 API and CAN serve the login form / let the user
// re-auth. The shell polls /healthz looking for "anyone home"; using
// 503 here makes the WebView's r.ok check false and the shell stays
// stuck on its loading card forever even though the user just needs
// to click into the SPA and log in. The earlier kubernetes-style
// "503=unhealthy" logic doesn't apply — there is no LB to drain.
//
// CORS: Access-Control-Allow-Origin:* — the Tauri shell at
// tauri://localhost polls this endpoint cross-origin to know when
// to navigate to the SPA at http://127.0.0.1:7400. Loopback-bound,
// so the wildcard isn't a real exposure.
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	s.state.mu.RLock()
	since := s.state.lifecycleAt
	started := s.state.startedAt
	s.state.mu.RUnlock()
	lc := s.state.LifecycleNow()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	body := map[string]any{
		"state":          lc.String(),
		"connected":      s.state.connected.Load(),
		"since":          since.Format(time.RFC3339),
		"started_at":     started.Format(time.RFC3339),
		"uptime_seconds": int64(time.Since(started).Seconds()),
		"version":        s.state.version,
		"server_addr":    s.state.serverAddr,
	}
	_ = json.NewEncoder(w).Encode(body)
}

func (s *Server) handleTunnels(w http.ResponseWriter, _ *http.Request) {
	snap := s.state.SnapshotNow()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(snap)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	// prefer the embedded SPA when available. Falls back to
	// the inline render in case the embed FS is empty (dev binary).
	if spaFS, err := UIFileSystem(); err == nil {
		if f, err := spaFS.Open("index.html"); err == nil {
			defer f.Close()
			if buf, err := io.ReadAll(f); err == nil && len(buf) > 0 {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = w.Write(buf)
				return
			}
		}
	}
	snap := s.state.SnapshotNow()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	renderIndex(w, snap)
}

// renderIndex writes a minimal HTML status page. We deliberately keep this
// in plain Go (no templates) so the binary stays small and the page is
// trivially printable from `curl /`.
func renderIndex(w http.ResponseWriter, snap Snapshot) {
	state := "DISCONNECTED"
	color := "#c0392b"
	if snap.Connected {
		state = "CONNECTED"
		color = "#27ae60"
	}
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>calabi status</title>
<style>
 body { font-family: -apple-system, BlinkMacSystemFont, "PingFang SC", "Microsoft YaHei", sans-serif; margin: 2rem; color: #222; }
 h1 { margin: 0 0 0.5rem; font-size: 1.4rem; }
 .badge { display: inline-block; padding: 2px 10px; border-radius: 12px; color: white; background: %s; font-size: 0.8rem; }
 table { border-collapse: collapse; margin-top: 1rem; }
 th, td { border: 1px solid #ddd; padding: 6px 12px; font-size: 0.9rem; text-align: left; }
 th { background: #f4f4f4; }
 footer { margin-top: 2rem; color: #888; font-size: 0.8rem; }
 a { color: #2980b9; text-decoration: none; }
</style>
</head>
<body>
<h1>calabi <span class="badge">%s</span></h1>
<p>%s · uptime %ds · server <code>%s</code></p>
`, color, state, snap.ClientVersion, snap.UptimeSeconds, snap.ServerAddr)

	if snap.SessionID != "" {
		fmt.Fprintf(w, `<p>session <code>%s</code> · tenant <code>%s</code> · client <code>%s</code></p>`,
			snap.SessionID, snap.TenantID, snap.ClientID)
	}

	if len(snap.Tunnels) == 0 {
		fmt.Fprintln(w, `<p><em>No tunnels registered yet.</em></p>`)
	} else {
		fmt.Fprintln(w, `<table>
<thead><tr><th>type</th><th>name</th><th>public</th><th>local</th><th>conns</th><th>bytes in</th><th>bytes out</th></tr></thead>
<tbody>`)
		for _, t := range snap.Tunnels {
			fmt.Fprintf(w,
				"<tr><td>%s</td><td>%s</td><td><code>%s</code></td><td><code>%s</code></td><td>%d</td><td>%d</td><td>%d</td></tr>\n",
				t.Type, t.Name, t.PublicAddr, t.LocalAddr, t.Connections, t.BytesIn, t.BytesOut)
		}
		fmt.Fprintln(w, `</tbody></table>`)
	}

	fmt.Fprintln(w, `<footer>
endpoints:
 <a href="/tunnels">/tunnels</a> ·
 <a href="/healthz">/healthz</a> ·
 <a href="/metrics">/metrics</a>
</footer>
</body></html>`)
}

func readBuildInfo() (goVer, revision string) {
	goVer = "unknown"
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	goVer = bi.GoVersion
	for _, s := range bi.Settings {
		if s.Key == "vcs.revision" {
			revision = s.Value
		}
	}
	return
}
