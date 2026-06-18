package main

// daemon_local_supervisor.go — the writable half of the local supervisor daemon. localSupervisor owns the mutable tunnel plan, persists console edits
// back to the YAML config, and drives a single-goroutine "reconcile" that brings
// the live edge session in line with the plan (register added / close removed /
// close+re-register policy-changed tunnels). It implements localweb.Lister +
// localweb.Writer so the SPA's create / delete / edit-security flows work in
// standalone.

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/calabi/calabi/apps/client/internal/localweb"
	"github.com/calabi/calabi/apps/client/internal/session"
	"github.com/calabi/calabi/apps/client/internal/status"
	"gopkg.in/yaml.v3"
)

type localSupervisor struct {
	logger      *slog.Logger
	base        localConfig // top-level config (server/token/insecure/ca) for persistence
	configPath  string
	server      string
	reconcileCh chan struct{} // nudged by write ops; drained by the session loop

	mu      sync.Mutex
	planned []plannedTunnel
	nextSeq int64              // monotonic id source for console-created tunnels
	live    map[int64]liveAddr // id → edge-assigned addr, set on register / cleared on close
}

// liveAddr is what the edge assigned a registered tunnel: the public domain
// (HTTP/SNI) and/or remote port (TCP/UDP). Presence in localSupervisor.live
// means the tunnel is currently registered on the session.
type liveAddr struct {
	domain     string
	remotePort uint32
}

func (sv *localSupervisor) markLive(id int64, a session.Assigned) {
	sv.mu.Lock()
	if sv.live == nil {
		sv.live = map[int64]liveAddr{}
	}
	sv.live[id] = liveAddr{domain: a.Domain, remotePort: a.RemotePort}
	sv.mu.Unlock()
}

func (sv *localSupervisor) markDead(id int64) {
	sv.mu.Lock()
	delete(sv.live, id)
	sv.mu.Unlock()
}

// recordAssignedAddr pins the edge-ASSIGNED domain (HTTP) / remote port (TCP/UDP)
// into the plan + YAML the FIRST time a tunnel registers without a configured
// one, so the subdomain/port stays STABLE across reconnects and restarts: next
// time the client requests that exact domain and the edge honors it (the edge
// only auto-allocates when the client sends none). No-op if the user configured
// one explicitly, or once it's already been pinned.
func (sv *localSupervisor) recordAssignedAddr(id int64, domain string, remotePort uint32) {
	sv.mu.Lock()
	changed := false
	for i := range sv.planned {
		p := &sv.planned[i]
		if p.id != id {
			continue
		}
		if domain != "" && p.yaml.Domain == "" {
			p.yaml.Domain, p.tun.Domain = domain, domain
			// The assigned domain already encodes any requested subdomain prefix
			// (<subdomain>.<base>); drop the now-redundant prefix so the persisted
			// config is unambiguous and Domain wins verbatim on the next boot.
			p.yaml.Subdomain, p.tun.Subdomain = "", ""
			changed = true
		}
		if remotePort != 0 && p.yaml.RemotePort == 0 {
			p.yaml.RemotePort, p.tun.RemotePort = remotePort, remotePort
			changed = true
		}
		break
	}
	sv.mu.Unlock()
	if changed {
		sv.persistBestEffort("pin-assigned-addr")
		sv.logger.Info("pinned edge-assigned address into config (stays stable across restarts)",
			"id", id, "domain", domain, "remote_port", remotePort)
	}
}

func newLocalSupervisor(logger *slog.Logger, base localConfig, configPath string, planned []plannedTunnel, server string) *localSupervisor {
	var maxID int64
	for _, p := range planned {
		if p.id > maxID {
			maxID = p.id
		}
	}
	return &localSupervisor{
		logger:      logger.With("component", "supervisor"),
		base:        base,
		configPath:  configPath,
		server:      server,
		reconcileCh: make(chan struct{}, 1),
		planned:     planned,
		nextSeq:     maxID,
	}
}

// snapshot returns a copy of the current plan for lock-free iteration.
func (sv *localSupervisor) snapshot() []plannedTunnel {
	sv.mu.Lock()
	defer sv.mu.Unlock()
	return append([]plannedTunnel(nil), sv.planned...)
}

// signalReconcile nudges the session loop to re-reconcile (non-blocking; a
// pending signal coalesces). When no session is live the buffered signal is
// harmlessly consumed by the next session's initial reconcile.
func (sv *localSupervisor) signalReconcile() {
	select {
	case sv.reconcileCh <- struct{}{}:
	default:
	}
}

// reconcile brings the live session in line with the plan. Runs ONLY on the
// session goroutine (runLocalSession), so registration ordering is single-
// threaded and race-free: the CLOSE_PROXY of a policy-changed tunnel is written
// to the ordered control stream before its replacement NEW_PROXY, so the edge
// frees the domain before re-registering it (no CodeProxyDuplicate).
func (sv *localSupervisor) reconcile(sctx context.Context, logger *slog.Logger, cli *session.Client, reg *localRegistry, state *status.State, server string) {
	plan := sv.snapshot()
	planByID := make(map[int64]plannedTunnel, len(plan))
	for _, p := range plan {
		planByID[p.id] = p
	}

	// 1) Close tunnels that were removed or whose policy changed.
	for id, e := range reg.liveIDs() {
		p, ok := planByID[id]
		switch {
		case !ok:
			_ = cli.CloseTunnel(e.proxyID, "console_delete")
			reg.removeID(id)
			sv.markDead(id)
			state.RemoveTunnel(e.proxyID)
			logger.Info("tunnel removed", "id", id)
		case p.tun.SecurityConfigJSON != e.configJSON || p.tun.LocalAddr != e.localAddr:
			_ = cli.CloseTunnel(e.proxyID, "console_update")
			reg.removeID(id)
			sv.markDead(id)
			state.RemoveTunnel(e.proxyID)
			logger.Info("tunnel config changed; re-registering", "id", id, "name", p.tun.Name,
				"local", p.tun.LocalAddr)
		}
	}

	// 2) Register new (and just-closed policy-changed) tunnels.
	edgeHost := hostOnly(server)
	for _, p := range plan {
		if sctx.Err() != nil {
			return
		}
		if reg.has(p.id) {
			continue
		}
		// Resolve a requested subdomain PREFIX to <subdomain>.<edge base_domain>
		// before NEW_PROXY (mirrors the platform edge's resolveProxyHost; the
		// wire frame carries only the full Domain). Domain wins when both are
		// set. base_domain comes from the edge's AUTH_RESP, always known here
		// since we only reconcile on a live session.
		eff := p.tun
		if eff.Domain == "" && eff.Subdomain != "" {
			eff.Domain = resolveSubdomainDomain(eff.Domain, eff.Subdomain, state.SnapshotNow().BaseDomain)
			if eff.Domain != "" {
				logger.Info("resolved subdomain to domain", "name", eff.Name, "subdomain", eff.Subdomain, "domain", eff.Domain)
			} else {
				logger.Warn("subdomain requested but edge advertised no base_domain; falling back to auto-assigned domain",
					"name", eff.Name, "subdomain", eff.Subdomain)
			}
		}
		assigned, err := cli.RegisterTunnelLive(sctx, eff, 0)
		if err != nil {
			logger.Error("register tunnel failed", "name", eff.Name, "type", p.kind, "err", err)
			continue
		}
		reg.set(p.id, assigned.ProxyID, p.tun.SecurityConfigJSON, p.tun)
		sv.markLive(p.id, assigned)
		sv.recordAssignedAddr(p.id, assigned.Domain, assigned.RemotePort)
		pub := localPublicAddr(p.kind, edgeHost, assigned)
		state.AddTunnel(status.TunnelInfo{
			ProxyID:    assigned.ProxyID,
			TunnelID:   p.id,
			Name:       p.tun.Name,
			Type:       p.kind,
			LocalAddr:  p.tun.LocalAddr,
			PublicAddr: pub,
		})
		logger.Info("tunnel up", "name", p.tun.Name, "type", p.kind, "local", p.tun.LocalAddr, "public", pub)
	}
}

// --- localweb.Lister --------------------------------------------------------

func (sv *localSupervisor) Tunnels() []localweb.ConfiguredTunnel {
	sv.mu.Lock()
	plan := append([]plannedTunnel(nil), sv.planned...)
	live := make(map[int64]liveAddr, len(sv.live))
	for k, v := range sv.live {
		live[k] = v
	}
	sv.mu.Unlock()

	out := make([]localweb.ConfiguredTunnel, 0, len(plan))
	for _, p := range plan {
		// Default to the configured values; once the tunnel is live, overlay the
		// edge-ASSIGNED domain / remote port (so the console shows the real public
		// address, e.g. an auto-assigned subdomain) and the edge id (so the Edge
		// column resolves instead of showing "—").
		domain, remotePort := p.tun.Domain, p.tun.RemotePort
		var edgeID int64
		if la, ok := live[p.id]; ok {
			if la.domain != "" {
				domain = la.domain
			}
			if la.remotePort != 0 {
				remotePort = la.remotePort
			}
			edgeID = localweb.SelfHostedEdgeID
		}
		out = append(out, localweb.ConfiguredTunnel{
			ID:         p.id,
			Name:       p.tun.Name,
			Type:       p.kind,
			LocalAddr:  p.tun.LocalAddr,
			Domain:     domain,
			RemotePort: remotePort,
			ConfigJSON: p.tun.SecurityConfigJSON,
			EdgeNodeID: edgeID,
		})
	}
	return out
}

// --- localweb.Writer --------------------------------------------------------

func (sv *localSupervisor) CreateTunnel(spec localweb.TunnelSpec) (int64, error) {
	// Safety: a console-created tunnel must forward to a local/intranet upstream,
	// not a public address (which would make the tunnel an open relay).
	if err := validateLocalUpstream(spec.LocalAddr); err != nil {
		return 0, err
	}
	tc := localTunnelConfig{
		Name:               spec.Name,
		Type:               spec.Type,
		Local:              spec.LocalAddr,
		Domain:             spec.Domain,
		Subdomain:          spec.Subdomain,
		RemotePort:         spec.RemotePort,
		SecurityConfigJSON: spec.ConfigJSON,
	}
	tun, err := toSessionTunnel(tc)
	if err != nil {
		return 0, err
	}
	sv.mu.Lock()
	sv.nextSeq++
	id := sv.nextSeq
	sv.planned = append(sv.planned, plannedTunnel{
		id:   id,
		kind: strings.ToLower(strings.TrimSpace(spec.Type)),
		tun:  tun,
		yaml: tc,
	})
	sv.mu.Unlock()
	sv.persistBestEffort("create")
	sv.signalReconcile()
	return id, nil
}

func (sv *localSupervisor) DeleteTunnel(id int64) error {
	sv.mu.Lock()
	out := make([]plannedTunnel, 0, len(sv.planned))
	found := false
	for _, p := range sv.planned {
		if p.id == id {
			found = true
			continue
		}
		out = append(out, p)
	}
	if !found {
		sv.mu.Unlock()
		return localweb.ErrTunnelNotFound
	}
	sv.planned = out
	sv.mu.Unlock()
	sv.persistBestEffort("delete")
	sv.signalReconcile()
	return nil
}

func (sv *localSupervisor) UpdateSecurity(id int64, configJSON string) error {
	sv.mu.Lock()
	idx := -1
	for i, p := range sv.planned {
		if p.id == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		sv.mu.Unlock()
		return localweb.ErrTunnelNotFound
	}
	p := sv.planned[idx]
	p.tun.SecurityConfigJSON = configJSON
	// Switch the persisted form to the raw blob — the structured `security:`
	// can't be rebuilt once passwords are hashed.
	p.yaml.Security = nil
	p.yaml.SecurityConfigJSON = configJSON
	sv.planned[idx] = p
	sv.mu.Unlock()
	sv.persistBestEffort("security update")
	sv.signalReconcile()
	return nil
}

// UpdateTunnel edits a tunnel's name + local_addr in place. An empty string
// leaves that field unchanged. A changed local_addr re-validates the local
// upstream and (via reconcile) re-homes the live tunnel; a name change is
// metadata only (the /v1/tunnels list reflects it immediately). Persisted so
// the edit survives a restart.
func (sv *localSupervisor) UpdateTunnel(id int64, name, localAddr string) error {
	if localAddr != "" {
		// Safety: same local/intranet guard as create — never let an edit point
		// the tunnel at a public address (open-relay risk).
		if err := validateLocalUpstream(localAddr); err != nil {
			return err
		}
	}
	sv.mu.Lock()
	idx := -1
	for i, p := range sv.planned {
		if p.id == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		sv.mu.Unlock()
		return localweb.ErrTunnelNotFound
	}
	p := sv.planned[idx]
	if name != "" {
		p.yaml.Name = name
	}
	if localAddr != "" {
		p.yaml.Local = localAddr
	}
	// Rebuild the live session tunnel from the edited YAML so local_addr is
	// normalized the same way create does (bare port → 127.0.0.1:port) — keeps
	// reconcile's local_addr comparison from seeing a spurious diff.
	tun, err := toSessionTunnel(p.yaml)
	if err != nil {
		sv.mu.Unlock()
		return err
	}
	p.tun = tun
	sv.planned[idx] = p
	sv.mu.Unlock()
	sv.persistBestEffort("edit")
	sv.signalReconcile()
	return nil
}

// --- persistence ------------------------------------------------------------

func (sv *localSupervisor) persistBestEffort(op string) {
	if err := sv.persist(); err != nil {
		sv.logger.Warn("persist config failed; change is live but won't survive restart",
			"op", op, "path", sv.configPath, "err", err)
	}
}

// persist rewrites the YAML config from the current plan. The top-level fields
// (server / token / token_env / insecure / ca_file) are preserved verbatim from
// the loaded config — notably token_env, so a secret kept out of the file stays
// out. Comments are NOT preserved (yaml.Marshal rebuilds the document); a header
// flags the file as console-managed.
func (sv *localSupervisor) persist() error {
	sv.mu.Lock()
	out := sv.base
	out.Tunnels = make([]localTunnelConfig, 0, len(sv.planned))
	for _, p := range sv.planned {
		out.Tunnels = append(out.Tunnels, p.yaml)
	}
	path := sv.configPath
	sv.mu.Unlock()

	data, err := yaml.Marshal(&out)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	const header = "# Managed by the calabi daemon console.\n" +
		"# Edits in the web UI rewrite this file (values preserved, comments not).\n\n"
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append([]byte(header), data...), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Compile-time assertions that the supervisor satisfies the localweb seams.
var (
	_ localweb.Lister = (*localSupervisor)(nil)
	_ localweb.Writer = (*localSupervisor)(nil)
)
