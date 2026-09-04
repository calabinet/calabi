// Platform daemon Connect (mesh) auto-enrollment.
//
// The local/standalone daemon joins its meshnet from a declarative `mesh:` YAML
// block (daemon_local_mesh.go). The PLATFORM daemon has no such block — it is
// driven by the control plane: on boot (and periodically) it asks bff-console
// "am I enrolled, and where's the coordinator?" and, when the answer is yes,
// brings the node onto its org's meshnet in the background alongside the tunnels.
//
// The node's coord auth key is the daemon's OWN data-plane credential (its tk_
// API key or login token): calabi-coord's platform authenticator resolves it via
// identity-svc to the owning org, which IS the meshnet (one org = one meshnet).
// So no separate key is minted — the same credential that authenticates the edge
// session and the /v1/mesh/enrollment fetch also enrolls the node. coord enforces
// the per-plan node cap at registration; the web console (MESH.8b/8e) is where a
// manager disables a node or edits ACLs. This file is the daemon's side: fetch +
// reconcile + surface status on :7400. Platform edition only.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/calabi/calabi/apps/client/internal/creds"
	"github.com/calabi/calabi/apps/client/internal/localweb"
	"github.com/calabi/calabi/apps/client/internal/mesh"
	"github.com/calabi/calabi/apps/client/internal/platform/statusapi"
)

// meshEnrollment is the control plane's answer to GET /v1/mesh/enrollment. When
// Enabled is false (org not entitled, or the platform hasn't wired a coordinator)
// the daemon stays off the mesh entirely.
type meshEnrollment struct {
	Enabled   bool   `json:"enabled"`
	CoordAddr string `json:"coord_addr"`
	RelayAddr string `json:"relay_addr"`
	NodeName  string `json:"node_name"` // optional; daemon falls back to hostname / --name
	// OrgID is the meshnet this enrollment is for (meshnet == org). It is the
	// ONLY field that changes when the operator switches org: coord/relay are
	// platform-wide and NodeName is the hostname. 0 from a bff that predates it.
	OrgID int64 `json:"org_id"`
}

// wantsRun reports whether this enrollment should bring the datapath up.
func (e meshEnrollment) wantsRun() bool {
	return e.Enabled && e.CoordAddr != "" && e.RelayAddr != ""
}

// meshLease is a running mesh session the controller can query + stop. The real
// implementation wraps *meshRunner; tests inject a fake so reconcile logic is
// exercised without a tun device.
// meshDeclUpdateTimeout bounds the declaration-update RPC. It is a single round
// trip on an already-open session; if it can't finish in this long, re-enrolling
// (the fallback) is the better answer anyway.
const meshDeclUpdateTimeout = 10 * time.Second

type meshLease interface {
	status() statusapi.MeshStatus
	// observations is the session's last service self-check, nil when it has not
	// run yet. Read by MeshServices so the local console can show what this
	// machine measured about its own services.
	observations() []mesh.ServiceObservation
	// updateDeclarations revises what this node declares WITHOUT restarting the
	// session. mesh.ErrNotEnrolled means the caller must re-enroll instead (no
	// session, unknown node, or a coordinator that predates the RPC).
	updateDeclarations(ctx context.Context, services []mesh.DeclaredService, fingerprint string) error
	stop()
}

// meshLeaseStarter starts a mesh session for the given config (coord/relay/name +
// any subnet-router / exit-node advertisement), with authKey supplying the coord
// auth key at each (re)registration. The daemon binds the session to ctx.
type meshLeaseStarter func(ctx context.Context, cfg meshConfig, authKey func() string) meshLease

// meshAdvertise is the node's optional subnet-router / exit-node role, set from
// the daemon's flags/env (see runDaemon). Zero value = a plain member node.
type meshAdvertise struct {
	Routes   []string // subnet-router CIDRs this node advertises (MESH.7a)
	ExitNode bool     // advertise this node AS an exit node (MESH.7b)
	ExitPeer string   // route THIS node's default traffic through this exit peer
}

// platformMeshController polls bff-console for the node's enrollment and keeps a
// mesh session running to match. It implements statusapi.MeshStatusSource so the
// :7400 console renders the node's live Connect state.
type platformMeshController struct {
	logger  *slog.Logger
	bffURL  string
	authKey func() string // bearer for the enrollment fetch AND the coord auth key
	name    string        // default node name (hostname / --name) when enrollment omits one
	start   meshLeaseStarter
	// services is what this machine's CONFIG declares it offers (--mesh-service
	// / env). Fixed for the process; the console-managed set lives in creds and
	// is read fresh, so both are merged at enrollment time.
	services []meshServiceDecl
	hc       *http.Client
	poll     time.Duration

	adv meshAdvertise // subnet-router / exit-node role (from daemon flags/env)

	mu    sync.Mutex
	ctx   context.Context // captured in Run; the lease is bound to it
	lease meshLease
	// leaseOrgID is the meshnet the running lease enrolled into. Compared
	// against fresh enrollments to catch an org switch; also reported in
	// MeshStatus so the console shows what is ACTUALLY running.
	leaseOrgID int64
	cur        meshEnrollment // last APPLIED enrollment (for change detection)
	homePref   string         // last APPLIED relay-home bias ("own"/"platform"); a change re-homes
	homePin    string         // last APPLIED facility pin (relay region); a change re-homes
	routeSig   string         // last APPLIED consumer route policy; a change re-installs
	// deviceFP is the Publish-side fingerprint the RUNNING session registered
	// with. It is read from creds at session start, and on a fresh install the
	// mesh comes up BEFORE the device registration that mints it — so the first
	// session registers with "" and the console shows the device with no link to
	// its client record until something restarts the session. Watching it here
	// makes that self-heal within the same boot.
	deviceFP string
	paused   bool // local `mesh down` — no re-enroll until daemon restart
}

// meshHomePreference maps the daemon's persisted edge affinity (creds
// PreferPlatformEdge) onto the mesh relay-home bias, so flipping 数据出口
// own/platform moves the relay home the same way the edge egress moves — "use my
// node" switches edge AND relay together. Defaults to "own" (the BYOI default)
// when creds can't be read; for an org with no self-hosted relay this is a no-op
// (there is no "self-" region to prefer, so selection stays pure-latency).
func meshHomePreference() string {
	if c, err := creds.Load(); err == nil && c != nil && c.PreferPlatformEdge {
		return "platform"
	}
	return "own"
}

// meshRoutePolicySettings reads this node's consumer-side route stance from
// creds. A nil accept means "never decided" and is passed through untouched —
// resolveAcceptRoutes owns the upgrade seed, and deciding it in two places is how
// the two would eventually disagree.
func meshRoutePolicySettings() (*bool, []string) {
	c, err := creds.Load()
	if err != nil || c == nil {
		return nil, nil
	}
	return c.MeshAcceptRoutes, c.MeshRouteExcludes
}

// routePolicySignature renders the policy for change detection. nil (undecided)
// is distinct from an explicit false: the seed runs once and writing it must not
// look like a policy change and bounce the session.
func routePolicySignature(accept *bool, excludes []string) string {
	s := "unset"
	if accept != nil {
		s = strconv.FormatBool(*accept)
	}
	return s + "|" + strings.Join(excludes, ",")
}

// meshHomePin resolves the relay region in the same facility as the edge this
// daemon is anchored to, so switching self-hosted node moves BOTH roles.
//
// LastEdgeRegion (where the edge session actually connected) is preferred over
// EdgeRegion (what was asked for): the relay should follow the edge to a
// facility that answered, not to one the daemon is still failing to reach.
// EdgeRegion covers the gap before the first successful connect. Reconcile polls
// every 30s, so the relay follows an edge switch within that.
func meshHomePin() string {
	c, err := creds.Load()
	if err != nil || c == nil {
		return ""
	}
	region := strings.TrimSpace(c.LastEdgeRegion)
	if region == "" {
		region = strings.TrimSpace(c.EdgeRegion)
	}
	return mesh.FacilityRelayRegion(region, c.PreferPlatformEdge)
}

// newPlatformMeshController builds the controller (not started). authKey returns
// the daemon's current data-plane credential ("" when there is none yet, e.g.
// pre-login — the poll then just retries). name is the default node name; adv is
// the optional subnet-router / exit-node role.
func newPlatformMeshController(logger *slog.Logger, bffURL string, authKey func() string, name string, adv meshAdvertise, services []meshServiceDecl) *platformMeshController {
	return &platformMeshController{
		logger:   logger.With("component", "mesh.enroll"),
		bffURL:   strings.TrimRight(bffURL, "/"),
		authKey:  authKey,
		name:     name,
		adv:      adv,
		start:    realMeshLeaseStarter(logger),
		services: services,
		hc:       &http.Client{Timeout: 10 * time.Second},
		poll:     30 * time.Second,
	}
}

// Run polls enrollment on a ticker (plus once immediately) and reconciles the
// running session to match, until ctx is cancelled. Blocking; call in a goroutine.
func (c *platformMeshController) Run(ctx context.Context) {
	c.mu.Lock()
	c.ctx = ctx
	c.mu.Unlock()

	c.tick(ctx)
	t := time.NewTicker(c.poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			c.shutdown()
			return
		case <-t.C:
			c.tick(ctx)
		}
	}
}

// tick fetches enrollment and reconciles. A fetch error keeps the current state
// (a bff-console blip must not tear a live meshnet down); it is logged at debug.
func (c *platformMeshController) tick(ctx context.Context) {
	enr, err := c.fetch(ctx)
	if err != nil {
		c.logger.Debug("mesh enrollment fetch failed; keeping current state", "err", err)
		return
	}
	c.reconcile(ctx, enr)
}

// fetch calls GET /v1/mesh/enrollment with the daemon's credential. An empty
// credential (pre-login) or non-200 is an error so tick keeps the prior state.
func (c *platformMeshController) fetch(ctx context.Context) (meshEnrollment, error) {
	if c.bffURL == "" {
		return meshEnrollment{}, fmt.Errorf("no bff-console URL")
	}
	tok := ""
	if c.authKey != nil {
		tok = c.authKey()
	}
	if tok == "" {
		return meshEnrollment{}, fmt.Errorf("no credential yet")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.bffURL+"/v1/mesh/enrollment", nil)
	if err != nil {
		return meshEnrollment{}, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return meshEnrollment{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		return meshEnrollment{}, fmt.Errorf("enrollment: %s", resp.Status)
	}
	var enr meshEnrollment
	if err := json.Unmarshal(body, &enr); err != nil {
		return meshEnrollment{}, fmt.Errorf("decode enrollment: %w", err)
	}
	return enr, nil
}

// reconcile brings the running session in line with the desired enrollment:
// start when newly enabled, restart when the coordinator/relay/name changes, and
// stop when disabled or locally paused.
func (c *platformMeshController) reconcile(ctx context.Context, enr meshEnrollment) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.paused {
		c.stopLocked("locally paused")
		return
	}
	if !enr.wantsRun() {
		c.stopLocked("enrollment disabled")
		c.cur = enr
		return
	}
	// Enabled. (Re)start only when nothing is running or the target changed —
	// otherwise a steady poll must not churn the datapath.
	name := c.name
	if enr.NodeName != "" {
		name = enr.NodeName
	}
	// An org switch changes WHICH meshnet this daemon belongs to and nothing
	// else, so without the org comparison the enrollment answer is identical
	// and the session keeps running against the PREVIOUS org's meshnet — then
	// silently jumps to the new one at the next reconnect, because runOnce
	// re-reads the credential. Comparing against the RUNNING lease's org (not
	// the last observed enrollment) means a restart that failed to happen is
	// caught on the following tick instead of being masked.
	//
	// 0 means "this control plane doesn't report it" (an older bff), which must
	// NOT read as "a different org" — otherwise every daemon in the fleet churns
	// its datapath once the moment bff-console is upgraded.
	orgChanged := enr.OrgID != 0 && c.leaseOrgID != 0 && enr.OrgID != c.leaseOrgID
	// A flip of the edge affinity must re-home the relay too (the co-switch), so
	// it counts as a change even when coord/relay/name/org are identical. Same for
	// a move between two SELF-HOSTED facilities, which the class preference alone
	// cannot see — both are "own", so without the pin the relay stayed wherever it
	// had measured fastest while the edge moved to the other site.
	pref := meshHomePreference()
	pin := meshHomePin()
	// The consumer-side route policy is part of the session too: turning
	// acceptance off (or excluding a prefix) has to pull those routes back out of
	// the kernel table, and a fresh session is what makes that happen — the new
	// netmap's config no longer carries them, so the withdrawal diff removes them.
	accept, excludes := meshRoutePolicySettings()
	sig := routePolicySignature(accept, excludes)
	// The device fingerprint reaches coord only at registration, so learning it
	// after the session started needs a new session. ONE DIRECTION ONLY: ""
	// → non-empty restarts, non-empty → "" does not. The empty value is what a
	// daemon reports when it has no registration YET *and* what it reports when
	// creds momentarily won't load, and tearing down a working mesh over the
	// second case would be a self-inflicted outage.
	fp := resolveFingerprint(c.logger)
	// A fingerprint that shows up mid-session is a DECLARATION change, so it goes
	// out through the cheap path too — no reason to churn the datapath for a
	// display-only value. Falling back to a restart keeps the old behaviour when
	// the coordinator can't take the update.
	if fp != "" && c.deviceFP == "" && c.lease != nil {
		uctx, cancel := context.WithTimeout(ctx, meshDeclUpdateTimeout)
		err := c.lease.updateDeclarations(uctx, declaredServices(c.declaredServices()), fp)
		cancel()
		if err == nil {
			c.logger.Info("mesh: device registration completed since we enrolled; reported the fingerprint without re-enrolling")
			c.deviceFP = fp
		} else {
			c.logger.Info("mesh: could not report the new fingerprint in place; re-enrolling", "err", err)
		}
	}
	// Only a fingerprint arriving on a RUNNING session is news. With no lease we
	// are enrolling for the first time and it rides that registration anyway —
	// reporting it as "registration completed since we enrolled" claimed a
	// re-enrollment that never happened, which is exactly the wrong thing to read
	// in a log while chasing a missing link.
	fpArrived := fp != "" && c.deviceFP == "" && c.lease != nil
	changed := c.lease == nil ||
		orgChanged ||
		fpArrived ||
		enr.CoordAddr != c.cur.CoordAddr ||
		enr.RelayAddr != c.cur.RelayAddr ||
		enr.NodeName != c.cur.NodeName ||
		pref != c.homePref ||
		pin != c.homePin ||
		sig != c.routeSig
	if !changed {
		// First time we learn the org for a session that started before the
		// control plane reported it: adopt it WITHOUT restarting. The lease
		// really is enrolled in that meshnet — we just had no way to know — so
		// recording it is accurate, and it stops leaseOrgID from being stuck at
		// "unknown" forever, which would blind the comparison above for the rest
		// of this session.
		if c.leaseOrgID == 0 && enr.OrgID != 0 {
			c.leaseOrgID = enr.OrgID
		}
		c.cur = enr
		return
	}
	if c.lease != nil {
		c.lease.stop()
		c.lease = nil
	}
	cfg := meshConfig{
		Enabled:           true,
		Coord:             enr.CoordAddr,
		Relay:             enr.RelayAddr,
		Name:              name,
		AdvertiseRoutes:   c.adv.Routes,
		AdvertiseExitNode: c.adv.ExitNode,
		ExitNode:          c.adv.ExitPeer,
		Services:          c.declaredServices(),
		HomePreference:    pref,
		PinnedHomeRegion:  pin,
		AcceptRoutes:      accept,
		RouteExcludes:     excludes,
	}
	if fpArrived {
		c.logger.Info("mesh: could not report the fingerprint in place; re-enrolling so the console can link this node to its client record")
	}
	c.logger.Info("mesh: enrolling node onto meshnet",
		"coord", enr.CoordAddr, "relay", enr.RelayAddr, "name", name, "org_id", enr.OrgID,
		"advertise_routes", c.adv.Routes, "advertise_exit_node", c.adv.ExitNode, "exit_node", c.adv.ExitPeer)
	c.lease = c.start(ctx, cfg, c.authKey)
	c.leaseOrgID = enr.OrgID
	c.cur = enr
	c.homePref = pref
	c.homePin = pin
	c.routeSig = sig
	// Only record a fingerprint we actually have. Storing "" would be accurate
	// but pointless; leaving the previous value in place is what keeps a later
	// creds hiccup from looking like an arrival and churning the session.
	if fp != "" {
		c.deviceFP = fp
	}
}

// stopLocked tears down any running session. Caller holds c.mu.
func (c *platformMeshController) stopLocked(reason string) {
	c.leaseOrgID = 0
	// Nothing is registered any more, so the next enrollment starts from
	// scratch — including the "" → fingerprint transition.
	c.deviceFP = ""
	if c.lease != nil {
		c.logger.Info("mesh: leaving meshnet", "reason", reason)
		c.lease.stop()
		c.lease = nil
	}
}

// shutdown stops the session on daemon exit.
func (c *platformMeshController) shutdown() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stopLocked("daemon shutdown")
}

// MeshStatus implements statusapi.MeshStatusSource: the node's live Connect state.
// When nothing is running it reports Enabled:false, carrying Paused so the console
// can tell a local stop (offer Start) from "never enrolled" (unavailable).
func (c *platformMeshController) MeshStatus() statusapi.MeshStatus {
	c.mu.Lock()
	lease, paused, org := c.lease, c.paused, c.leaseOrgID
	c.mu.Unlock()
	if lease == nil {
		return statusapi.MeshStatus{Enabled: false, Paused: paused, Peers: []statusapi.MeshPeer{}}
	}
	st := lease.status()
	// The lease itself doesn't know its org (the runner only sees coord/relay/
	// name); the controller is what enrolled it, so it stamps the org here.
	st.OrgID = org
	return st
}

// MeshDown implements statusapi.MeshStatusSource: pause local participation
// (leave the meshnet, stop re-enrolling). Reversible with MeshUp.
func (c *platformMeshController) MeshDown() error {
	c.mu.Lock()
	c.paused = true
	c.stopLocked("mesh down (local)")
	c.mu.Unlock()
	return nil
}

// MeshUp implements statusapi.MeshStatusSource: resume after a MeshDown — clear the
// pause and re-enroll right away instead of waiting for the next poll tick.
func (c *platformMeshController) MeshUp() error {
	c.mu.Lock()
	c.paused = false
	ctx := c.ctx
	c.mu.Unlock()
	if ctx != nil {
		c.tick(ctx) // immediate enrollment fetch + reconcile
	}
	return nil
}

// declaredServices merges the two declaration sources: the config/flag set
// (fixed for this process) and the set managed from the local console (creds,
// re-read each time so a UI edit takes effect on the next enrollment). The
// config wins a name clash — the file re-declares it at every restart anyway,
// so letting the console shadow it would just produce a value that flips back.
func (c *platformMeshController) declaredServices() []meshServiceDecl {
	out := append([]meshServiceDecl(nil), c.services...)
	seen := make(map[string]bool, len(out))
	for _, s := range out {
		seen[s.Name] = true
	}
	cfg, err := creds.Load()
	if err != nil || cfg == nil {
		return out
	}
	for _, s := range cfg.MeshServices {
		if seen[s.Name] {
			continue
		}
		out = append(out, meshServiceDecl{Name: s.Name, Proto: s.Proto, Port: s.Port, Target: s.Target, Note: s.Note})
	}
	return out
}

// MeshServices implements statusapi.MeshStatusSource: what this machine
// declares, with the config-sourced entries marked so the console can show them
// read-only.
func (c *platformMeshController) MeshServices() []statusapi.MeshServiceDecl {
	fromCfg := make(map[string]bool, len(c.services))
	for _, s := range c.services {
		fromCfg[s.Name] = true
	}
	c.mu.Lock()
	lease := c.lease
	c.mu.Unlock()
	var obs []mesh.ServiceObservation
	if lease != nil {
		obs = lease.observations()
	}
	health := make(map[string]mesh.ServiceHealthReport, len(obs))
	for _, o := range obs {
		health[o.Service.Name] = o.Health
	}

	all := c.declaredServices()
	out := make([]statusapi.MeshServiceDecl, 0, len(all))
	declared := make(map[string]bool, len(all))
	for _, s := range all {
		declared[s.Name] = true
		h := health[s.Name]
		out = append(out, statusapi.MeshServiceDecl{
			Name: s.Name, Proto: s.Proto, Port: s.Port, Target: s.Target, Note: s.Note,
			FromConfig: fromCfg[s.Name],
			Checked:    h.Checked, TargetOK: h.TargetOK, MeshOK: h.MeshOK,
		})
	}
	// Services a manager registered in the web console. They are checked by this
	// machine like any other, so listing them here is the difference between the
	// operator seeing what their machine offers and seeing only half of it —
	// and the half they can't see is the one nobody at the machine set up.
	for _, o := range obs {
		// The flag, not "absent from the declarations": subtracting the two
		// lists mislabels a service that was just REMOVED locally, whose
		// observation outlives it by one check cycle.
		if !o.FromNetmap || declared[o.Service.Name] {
			continue
		}
		out = append(out, statusapi.MeshServiceDecl{
			Name: o.Service.Name, Proto: o.Service.Proto, Port: o.Service.Port,
			Target: o.Service.Target, Note: o.Service.Note,
			FromConsole: true,
			Checked:     o.Health.Checked, TargetOK: o.Health.TargetOK, MeshOK: o.Health.MeshOK,
		})
	}
	return out
}

// SetMeshServices implements statusapi.MeshStatusSource: persist the
// console-managed declarations and restart the session so they are re-declared.
// Config-sourced entries are not stored — the file owns them.
func (c *platformMeshController) SetMeshServices(in []statusapi.MeshServiceDecl) error {
	cfg, _ := creds.Load()
	if cfg == nil {
		cfg = &creds.Config{}
	}
	out := make([]creds.MeshServiceDecl, 0, len(in))
	for _, s := range in {
		// Neither source is this list's to own. The config file re-declares its
		// entries at every restart; a console-registered one would become a
		// SECOND row claiming that name, and only one of the two would carry the
		// authorization.
		if s.FromConfig || s.FromConsole {
			continue
		}
		out = append(out, creds.MeshServiceDecl{Name: s.Name, Proto: s.Proto, Port: s.Port, Target: s.Target, Note: s.Note})
	}
	cfg.MeshServices = out
	if err := creds.Save(cfg); err != nil {
		return fmt.Errorf("persist mesh services: %w", err)
	}
	// Declarations reach the coordinator through their own RPC now, so an edit
	// costs one round trip instead of a full re-enrollment (which reconfigures
	// WireGuard, re-dials every relay and re-punches every direct path — seconds
	// of disrupted traffic for a change that moves no addresses).
	//
	// Re-enrolling is still the fallback, and it has to be: an older coordinator
	// answers Unimplemented, and a node the coordinator doesn't know can only be
	// fixed by enrolling. Either way the edit lands.
	// declaredServices reads c.services, so snapshot it under the lock — and
	// release before the RPC, which must not be held across a network call.
	c.mu.Lock()
	lease, lctx, decls := c.lease, c.ctx, declaredServices(c.declaredServices())
	c.mu.Unlock()
	if lease != nil && lctx != nil {
		uctx, cancel := context.WithTimeout(lctx, meshDeclUpdateTimeout)
		err := lease.updateDeclarations(uctx, decls, resolveFingerprint(c.logger))
		cancel()
		if err == nil {
			return nil
		}
		c.logger.Info("mesh: declaration update unavailable; re-enrolling instead", "err", err)
	}
	c.Rebind("mesh services changed")
	return nil
}

// Rebind drops the running mesh session so the next reconcile re-enrolls with
// whatever credential is now on disk. Called when the daemon's IDENTITY changes
// (login / logout / org switch): the credential is re-read per session, so the
// running session would otherwise stay on the old meshnet until it happened to
// reconnect — and then jump orgs at an unpredictable moment.
//
// Respects a local pause: a paused node stays paused. On logout the follow-up
// enrollment fetch fails, which correctly leaves mesh down until the next login.
func (c *platformMeshController) Rebind(reason string) {
	c.mu.Lock()
	if c.lease != nil {
		c.logger.Info("mesh: identity changed; leaving meshnet to re-enroll", "reason", reason, "org_id", c.leaseOrgID)
		c.stopLocked(reason)
	}
	ctx := c.ctx
	c.mu.Unlock()
	if ctx != nil {
		c.tick(ctx) // re-enroll now rather than at the next 30s poll
	}
}

// Nudge re-reconciles the meshnet session NOW instead of at the next 30s poll,
// so an edge-affinity flip moves the relay home promptly (the co-switch: "use my
// node" switches edge egress AND relay home together). Unlike Rebind it does not
// tear the session down first — reconcile restarts it only if something it
// watches actually changed, and the home preference (creds.PreferPlatformEdge)
// is one of those. A no-op when nothing changed, so it is safe to call on any
// egress/region switch. Runs a fetch, so callers on an HTTP path invoke it in a
// goroutine.
func (c *platformMeshController) Nudge() {
	c.mu.Lock()
	ctx := c.ctx
	c.mu.Unlock()
	if ctx != nil {
		c.tick(ctx)
	}
}

// Advertise implements statusapi.MeshStatusSource: this node's current
// subnet-router / exit-node role.
func (c *platformMeshController) Advertise() statusapi.MeshAdvertise {
	c.mu.Lock()
	defer c.mu.Unlock()
	return statusapi.MeshAdvertise{
		Routes:   append([]string(nil), c.adv.Routes...),
		ExitNode: c.adv.ExitNode,
		ExitPeer: c.adv.ExitPeer,
	}
}

// SetAdvertise implements statusapi.MeshStatusSource: update the role and restart
// the mesh session so the new advertisement re-registers (and re-applies NAT).
// Respects a local pause — the new role takes effect when the operator starts it
// again. The caller (statusapi) has already persisted it to creds.
func (c *platformMeshController) SetAdvertise(a statusapi.MeshAdvertise) error {
	c.mu.Lock()
	c.adv = meshAdvertise{Routes: append([]string(nil), a.Routes...), ExitNode: a.ExitNode, ExitPeer: a.ExitPeer}
	// Drop the running session so reconcile restarts it with the new role (a nil
	// lease forces the change). Don't touch paused — a paused node stays paused.
	if c.lease != nil {
		c.lease.stop()
		c.lease = nil
	}
	ctx := c.ctx
	c.mu.Unlock()
	if ctx != nil {
		c.tick(ctx)
	}
	return nil
}

// realMeshLeaseStarter builds the production lease: a meshRunner whose auth key is
// the daemon's live credential, started in the background.
func realMeshLeaseStarter(logger *slog.Logger) meshLeaseStarter {
	return func(ctx context.Context, cfg meshConfig, authKey func() string) meshLease {
		r := newMeshRunner(logger, cfg)
		r.authKeyFn = authKey
		r.Start(ctx)
		return &runnerLease{r: r}
	}
}

// runnerLease adapts *meshRunner to meshLease (localweb.MeshStatus → statusapi).
type runnerLease struct{ r *meshRunner }

func (l *runnerLease) stop() { l.r.Stop() }

func (l *runnerLease) updateDeclarations(ctx context.Context, services []mesh.DeclaredService, fingerprint string) error {
	return l.r.UpdateDeclarations(ctx, services, fingerprint)
}

func (l *runnerLease) observations() []mesh.ServiceObservation {
	return l.r.ServiceObservations()
}

func (l *runnerLease) status() statusapi.MeshStatus {
	return toStatusapiMesh(l.r.MeshStatus())
}

// toStatusapiMesh converts the localweb status shape (what meshRunner produces)
// into the statusapi shape (what the platform daemon's /v1/mesh serves). The two
// are field-identical; this keeps statusapi from importing localweb.
func toStatusapiMesh(m localweb.MeshStatus) statusapi.MeshStatus {
	peers := make([]statusapi.MeshPeer, 0, len(m.Peers))
	for _, p := range m.Peers {
		peers = append(peers, statusapi.MeshPeer{
			PublicKey:        p.PublicKey,
			AllowedIPs:       p.AllowedIPs,
			LastHandshakeSec: p.LastHandshakeSec,
			RxBytes:          p.RxBytes,
			TxBytes:          p.TxBytes,
			Path:             p.Path,
			Endpoint:         p.Endpoint,
		})
	}
	return statusapi.MeshStatus{
		Enabled:  m.Enabled,
		Up:       m.Up,
		Coord:    m.Coord,
		Relay:    m.Relay,
		DerpHome: m.DerpHome,
		Name:     m.Name,
		Overlay:  m.Overlay,
		Peers:    peers,
	}
}
