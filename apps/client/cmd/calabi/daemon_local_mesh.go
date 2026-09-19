// daemon_local_mesh.go — the WireGuard mesh inside the local daemon.
//
// The local supervisor daemon (daemon_local.go) manages the Publish data plane
// (reverse tunnels). This wires the SECOND data plane, the mesh, into the
// same long-lived process: a declarative `mesh:` block in the daemon YAML brings
// the node onto its meshnet in the background, and — via `calabi daemon install`
// — as a boot-start service. Same binary, one daemon, both data planes.
//
// Compiled into both deployments (mesh is the open data plane). Needs a tun device
// + privileges, like `calabi mesh up`; the datapath's runtime is verified in
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/calabi/calabi/apps/client/internal/creds"
	"github.com/calabi/calabi/apps/client/internal/localweb"
	"github.com/calabi/calabi/apps/client/internal/mesh"
	"github.com/calabi/calabi/apps/client/internal/platform/meshenroll"
	"github.com/calabi/calabi/apps/client/internal/selfhosted"
	"github.com/calabi/calabi/apps/client/internal/trust"
)

// meshConfig is the daemon YAML `mesh:` block. Empty/disabled = the daemon runs
// tunnels only (no mesh), exactly as before.
type meshConfig struct {
	Enabled bool   `yaml:"enabled,omitempty"`
	Coord   string `yaml:"coord,omitempty"`    // coordinator host:port (prod: your bff-console entrypoint)
	Relay   string `yaml:"relay,omitempty"`    // relay host:port to start on; optional — else the coordinator's relay map decides
	AuthKey string `yaml:"auth_key,omitempty"` // tk_ key (platform) or pre-shared key (self-hosted)
	// Trust, Pins and CAFile say how the coordinator's certificate is checked: trust is "system", "pin"
	// (with pins), "ca" (with ca_file), "plaintext" or "platform". Unset, the
	// daemon decides; see coordTrust.
	Trust  string   `yaml:"trust,omitempty"`
	Pins   []string `yaml:"pins,omitempty"`
	CAFile string   `yaml:"ca_file,omitempty"`
	// PlatformCoord marks a lease the platform daemon built from its own
	// enrollment: the coordinator is calabi.net's. Code-only, hence yaml:"-".
	PlatformCoord bool   `yaml:"-"`
	Name          string `yaml:"name,omitempty"`     // node name for MagicDNS; defaults to hostname
	KeyFile       string `yaml:"key_file,omitempty"` // WireGuard private key path; default per-OS config dir
	// AdvertiseRoutes are subnet-router CIDRs this node offers to forward (MESH.7),
	// e.g. ["192.168.1.0/24"]. Enables local forwarding + NAT on Linux.
	AdvertiseRoutes []string `yaml:"advertise_routes,omitempty"`
	// AliasRoutes is IGNORED. Every advertised route is now published under a
	// stand-in prefix wherever the host can install the rewrite, so there is no
	// subset to pick (see runMeshFromConfig). The field is kept only so a config
	// file written when this WAS a choice still parses instead of failing the
	// daemon on an unknown key.
	AliasRoutes []string `yaml:"alias_routes,omitempty"`
	// MTU overrides the tun MTU (mesh.DefaultMTU when unset or unusable). A
	// diagnostic knob: a path whose real MTU is below the default black-holes
	// every full-size packet while pings sail through, and lowering this is how
	// that gets confirmed.
	MTU int `yaml:"mtu,omitempty"`
	// AdvertiseExitNode offers this node as an exit node (forward peers' default
	// route to the internet) — sugar for advertising 0.0.0.0/0 (MESH.7b).
	AdvertiseExitNode bool `yaml:"advertise_exit_node,omitempty"`
	// ExitNode routes THIS node's default traffic through the named exit-node peer
	// (name or overlay IP). Opt-in: an advertised exit node is never used unless set.
	ExitNode string `yaml:"exit_node,omitempty"`
	// MagicDNS opts this node into rewriting the SYSTEM resolver config so mesh
	// node names resolve (`ssh web-01.mesh`). Default OFF, and the default is the
	// decision: MagicDNS was withdrawn from every piece of customer-facing
	// documentation on 2026-09-07 because the machines that
	// want to type such an address are overwhelmingly Windows and macOS, where it
	// was never implemented. The code kept running on Linux anyway, so the feature
	// carried its whole downside — it takes over /etc/resolv.conf, and an
	// ungraceful exit leaves the host with NO DNS AT ALL — in exchange for a
	// benefit we had stopped promising. Field report 2026-09-09.
	//
	// Left as a switch rather than deleted: the implementation is fine, the
	// product decision is what changed, and A1 (split-horizon DNS) will want it.
	MagicDNS bool `yaml:"magic_dns,omitempty"`
	// HomePreference biases mesh relay-home selection to match the edge affinity,
	// so "use my node" moves BOTH the edge egress and the relay home ("own" =
	// prefer the org's self-hosted relay, "platform" = prefer the platform's).
	// Set programmatically from creds in the platform path; empty when self-hosted
	// (no platform-vs-own distinction), hence yaml:"-" — it's never a file knob.
	HomePreference string `yaml:"-"`
	// AcceptRoutes decides whether this node installs the subnet routes its PEERS
	// advertise (the consumer side of MESH.7). nil = not configured, which the
	// daemon resolves once at startup and remembers; see resolveAcceptRoutes.
	// Advertising is the publisher's call and approval the admin's — this is the
	// receiving machine's, because the route lands in ITS kernel routing table.
	AcceptRoutes *bool `yaml:"accept_routes,omitempty"`
	// RouteExcludes refuses individual prefixes while still accepting the rest,
	// e.g. ["192.168.1.22/32"]. Contains-or-equal: excluding a /24 also refuses
	// every more-specific prefix inside it.
	RouteExcludes []string `yaml:"route_excludes,omitempty"`
	// BlockIncoming refuses every inbound CONNECTION to this machine, whatever
	// the org's access rules allow; replies to conversations this machine started
	// still come back. The consumer side again, and for the same reason: an
	// admin's "accept" is permission to try, not an obligation on this machine to
	// answer. Platform path sets it from creds (the console switch); a
	// self-hosted config can set it here.
	BlockIncoming bool `yaml:"block_incoming,omitempty"`
	// PinnedHomeRegion pins the relay home to the facility the EDGE session is
	// anchored to, so switching between two self-hosted nodes moves the relay
	// with the edge instead of leaving it wherever it measured fastest. Set
	// programmatically from creds (platform path only), hence yaml:"-".
	PinnedHomeRegion string `yaml:"-"`
	// Services declares what this machine OFFERS on the mesh, e.g.
	//   services:
	//     - {name: db, proto: tcp, port: 5432, note: "prod primary"}
	// A DECLARATION, not an authorization: the coordinator records each entry as
	// pending and an admin confirms it in the console before any ACL "svc:" rule
	// matches. Written by a person (or by IaC), never discovered by scanning the
	// machine — and
	Services []meshServiceDecl `yaml:"services,omitempty"`
}

// meshServiceDecl is one entry of meshConfig.Services.
type meshServiceDecl struct {
	Name  string `yaml:"name"`
	Proto string `yaml:"proto,omitempty"` // tcp (default) | udp
	Port  int    `yaml:"port"`
	// Target is what THIS machine dials to reach the application, e.g.
	// "127.0.0.1:5432" or a box on its LAN. Empty means 127.0.0.1:<port>.
	// Opening Port in the packet filter does nothing if the app is bound to
	// loopback only, which is why the two are separate.
	Target string `yaml:"target,omitempty"`
	Note   string `yaml:"note,omitempty"`
}

// complete reports whether the block has the minimum a node needs to join. The
// relay is not part of it: without one the node takes its home relay from the
// coordinator's relay map.
func (m meshConfig) complete() bool {
	return m.Coord != "" && m.AuthKey != ""
}

// coordTrust is how this node checks the coordinator's certificate.
func (m meshConfig) coordTrust(authKey string) (trust.Config, error) {
	return coordTrust(coordTrustSpec{Mode: m.Trust, Pins: m.Pins, CAFile: m.CAFile, Platform: m.PlatformCoord}, authKey)
}

// meshRunner owns the mesh subsystem's lifecycle inside the daemon: it brings the
// WireGuard datapath + coordinator controller up in the background and retries
// (backoff) on failure until Stop. The stable node key (LoadOrCreateKey) plus the
// coordinator's idempotent-by-key Register keep the node's overlay stable across
// reconnects.
type meshRunner struct {
	cfg    meshConfig
	logger *slog.Logger

	// authKeyFn, when set, supplies the coord auth key at each (re)registration
	// instead of the static cfg.AuthKey. The PLATFORM daemon uses this: its mesh
	// auth key is its own data-plane credential (the tk_ API key / login token),
	// resolved fresh per session so a refreshed access_token is picked up on the
	// next retry (coord resolves it to the org == meshnet via identity-svc). The
	// local/standalone daemon leaves it nil and uses cfg.AuthKey from its YAML.
	authKeyFn func() string

	// refreshFn, when set, is asked for a fresh credential after the coordinator
	// refuses the one authKeyFn returned; it returns the new credential, or ""
	// when there is nothing to do. The platform daemon sets it for a login
	// session — see refreshAfterDenial for why the mesh cannot wait for anyone
	// else to. refreshGate is its cooldown; loop goroutine only.
	refreshFn   func(context.Context) string
	refreshGate meshenroll.RefreshGate

	// reauth carries "this device is node N and may come back by proof alone"
	// from one session to the next, so a reconnect does not present the auth
	// key. One runner is one
	// meshnet: the platform lease builds a new runner when the org changes.
	reauth *mesh.ReauthState

	// tunnels, when set, are the tunnels this daemon serves, reported to a
	// self-hosted coordinator for the meshnet's phones. Only the local daemon sets
	// it; it outlives each session like reauth. A platform coordinator refuses
	// the report and the session stops sending it.
	tunnels *mesh.TunnelMeter

	// certs, when set, records that a self-hosted coordinator presented a
	// certificate the node's trust refuses (only the local daemon sets it; the
	// platform's coordinator is checked against the CA compiled in, and a
	// mismatch there is not the user's to accept). lastRegistered says whether
	// the session that just ended got as far as registering — one that did was
	// not stopped by the certificate.
	certs          *certWatch
	lastRegistered bool
	// lastErr is how the last session ended; r.mu.
	lastErr error

	// tune is the retry loop's knobs and steps; the zero value is production.
	// Only tests set it (see loop).
	tune meshLoopTuning

	mu      sync.Mutex
	dp      *mesh.WGDatapath // current datapath; nil while down/retrying
	ctrl    *mesh.Controller // current session's controller; nil while down/retrying
	cancel  context.CancelFunc
	done    chan struct{}
	started bool
}

// authKey returns the coord auth key for a registration: the dynamic provider
// when set (platform daemon), else the static config value (local daemon).
func (r *meshRunner) authKey() string {
	if r.authKeyFn != nil {
		if k := r.authKeyFn(); k != "" {
			return k
		}
	}
	return r.cfg.AuthKey
}

// newMeshRunner builds a runner (not yet started) so it can be handed to the
// localweb API as a MeshSource before the daemon's signal context exists. Call
// Start to launch it.
func newMeshRunner(logger *slog.Logger, cfg meshConfig) *meshRunner {
	return &meshRunner{cfg: cfg, logger: logger, reauth: mesh.NewReauthState(0, false, nil)}
}

// Start launches the background loop bound to parent's lifetime. Idempotent-safe
// to pair with Stop.
func (r *meshRunner) Start(parent context.Context) {
	ctx, cancel := context.WithCancel(parent)
	r.mu.Lock()
	r.cancel = cancel
	r.done = make(chan struct{})
	r.started = true
	r.mu.Unlock()
	go r.loop(ctx)
}

const (
	minMeshBackoff = 2 * time.Second
	maxMeshBackoff = 30 * time.Second
	// meshSessionHealthy is how long a control-plane session must have STOOD UP
	// for the connection to count as having worked. Past it, the next failure is
	// a fresh incident rather than the continuation of a crash loop, and the
	// backoff starts over. Without this a node that has been enrolled for hours
	// pays the 30s cap for a one-second hiccup, because the backoff only ever
	// doubled — nothing reset it.
	meshSessionHealthy = time.Minute
)

// meshDataPlane is the half of a mesh session that MUST OUTLIVE a control-plane
// reconnect: the tun device, the WireGuard device, MagicDNS, the subnet router.
//
// None of it is invalidated by the netmap stream dropping — the keys are the
// same, the peers are the same, the tunnel is still carrying traffic. Rebuilding
// it anyway (which is what this runner used to do, because one function owned
// both halves) destroys and recreates the tun interface, and every TCP
// connection bound to the overlay address dies with it. A coordinator blip would
// take out the very remote desktop the meshnet exists to carry.
type meshDataPlane struct {
	dp      *mesh.WGDatapath
	dns     mesh.DNSSink
	key     mesh.PrivateKey
	routes  []netip.Prefix
	aliases []netip.Prefix
	stop    func()
}

// meshLoopTuning is the retry loop's knobs and its two steps. The zero value is
// production; a test fills it in to drive the loop without a tun device and
// without waiting out real backoffs.
type meshLoopTuning struct {
	minBackoff     time.Duration
	maxBackoff     time.Duration
	healthySession time.Duration
	startDP        func() (*meshDataPlane, error)
	runCP          func(context.Context, *meshDataPlane) error
	sleep          func(context.Context, time.Duration) bool // false = shutting down
}

// loop brings the data plane up once and then keeps a control-plane session
// running against it, retrying with backoff until Stop.
func (r *meshRunner) loop(ctx context.Context) {
	defer close(r.done)
	t := r.tune
	if t.minBackoff == 0 {
		t.minBackoff = minMeshBackoff
	}
	if t.maxBackoff == 0 {
		t.maxBackoff = maxMeshBackoff
	}
	if t.healthySession == 0 {
		t.healthySession = meshSessionHealthy
	}
	if t.startDP == nil {
		t.startDP = r.startDataPlane
	}
	if t.runCP == nil {
		t.runCP = r.runControlPlane
	}
	if t.sleep == nil {
		t.sleep = sleepUnlessDone
	}

	var data *meshDataPlane
	defer func() {
		if data != nil {
			r.setDP(nil)
			data.stop()
		}
	}()

	backoff := t.minBackoff
	for ctx.Err() == nil {
		if data == nil {
			d, err := t.startDP()
			if err != nil {
				r.logger.Warn("mesh: data plane could not start; retrying", "backoff", backoff.String(), "err", err)
				if !t.sleep(ctx, backoff) {
					return
				}
				backoff = min(backoff*2, t.maxBackoff)
				continue
			}
			data = d
			r.setDP(d.dp)
		}

		started := time.Now()
		err := t.runCP(ctx, data)
		if ctx.Err() != nil {
			return
		}
		r.mu.Lock()
		r.lastErr = err
		r.mu.Unlock()
		if time.Since(started) >= t.healthySession {
			backoff = t.minBackoff // that session worked; don't punish the next one
		}
		if r.refreshAfterDenial(ctx, err) {
			backoff = t.minBackoff // a fresh credential is worth trying straight away
		}
		r.checkCoordCert(ctx)
		// Deliberately NOT an error about the mesh being down: the tun device,
		// the peers and the relay links are all still up and carrying traffic.
		// Only the coordinator connection is being re-established.
		r.logger.Warn("mesh: control-plane session ended; reconnecting (the tunnel stays up)",
			"backoff", backoff.String(), "err", err)
		if !t.sleep(ctx, backoff) {
			return
		}
		backoff = min(backoff*2, t.maxBackoff)
	}
}

// sleepUnlessDone waits out one retry delay. false means the runner is stopping.
func sleepUnlessDone(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// startDataPlane brings up everything that persists across control-plane
// reconnects. Its stop() undoes it all, in reverse.
func (r *meshRunner) startDataPlane() (*meshDataPlane, error) {
	keyFile := r.cfg.KeyFile
	if keyFile == "" {
		keyFile = defaultMeshKeyPath()
	}
	priv, err := mesh.LoadOrCreateKey(keyFile)
	if err != nil {
		return nil, fmt.Errorf("key: %w", err)
	}

	// Subnet router / exit node: advertise + forward the configured CIDRs (and
	// 0.0.0.0/0 when advertise_exit_node) with best-effort NAT. Parsed before the
	// tun comes up so a bad CIDR costs nothing.
	// A bad entry is DROPPED, not fatal. This list comes from a file, and the
	// width limit (mesh.AdvertiseMinBitsV4) arrived after those files did — a
	// subnet router that has published a /16 since before the rule would
	// otherwise fail to start its mesh session entirely, losing its overlay
	// address and every other route over one netmask. See mesh.SplitRouteList.
	routes, badRoutes := mesh.SplitRouteList(r.cfg.AdvertiseRoutes)
	if len(badRoutes) > 0 {
		r.logger.Warn("mesh: ignoring unusable subnet routes from the config",
			"advertise_routes", mesh.ProblemStrings(badRoutes))
	}
	// EVERY published route is aliased — this is not a setting.
	//
	// A route published under its real CIDR is unreachable from any peer whose
	// own LAN happens to use the same addresses, and neither the publisher nor
	// the coordinator can see whose does. Leaving that as a switch meant the
	// person who had to predict the collision was the one who could not observe
	// it, and the default (off) was the answer that breaks. Aliasing everything
	// costs one NAT hop and makes the rule uniform: peers always reach a subnet
	// at its stand-in prefix.
	//
	// The only remaining question is whether THIS machine can install the
	// rewrite, which is a fact about the host, not a preference — so it is
	// probed rather than configured. A host that cannot keeps publishing real
	// CIDRs, exactly as before aliases existed.
	var aliasRoutes []netip.Prefix
	if len(routes) > 0 {
		// Not-a-no, rather than a yes: an inconclusive probe (iptables could not
		// run just now) must not silently drop this node back to publishing real
		// CIDRs. Asking for the alias and failing to install it logs a warning
		// naming the reason; declining to ask logs nothing and looks like a
		// deliberate configuration.
		support, why := mesh.SubnetAliasSupport(r.logger)
		if support == mesh.AliasSupportNo {
			r.logger.Warn("mesh: this host cannot install subnet-alias rules; subnets are published under their "+
				"real addresses, so peers whose own LAN collides with them cannot reach them", "why", why)
		} else {
			aliasRoutes = routes
		}
	}
	if r.cfg.AdvertiseExitNode {
		routes = append(routes, netip.PrefixFrom(netip.IPv4Unspecified(), 0)) // 0.0.0.0/0
	}

	dp, err := mesh.NewWGDatapath(priv, r.cfg.Relay, resolveMeshMTU(r.cfg.MTU, r.logger), r.logger)
	if err != nil {
		return nil, fmt.Errorf("datapath: %w", err)
	}
	stops := []func(){func() { dp.Close() }}

	// MagicDNS: opt-in name resolution for peers. Mesh works without it, and NOT
	// running it is what keeps this daemon out of /etc/resolv.conf entirely — the
	// one file whose breakage costs the whole machine rather than the mesh.
	var dnsSink mesh.DNSSink
	if r.cfg.MagicDNS {
		if sink, cleanup, err := mesh.StartMagicDNS(r.logger); err != nil {
			logMagicDNSUnavailable(r.logger, err)
		} else {
			stops = append(stops, cleanup)
			dnsSink = sink
		}
	}

	if len(routes) > 0 {
		if cleanup, e := mesh.EnableSubnetRouter(priv.Public(), routes, r.logger); e != nil {
			r.logger.Warn("mesh: subnet-router forwarding not enabled; advertising anyway", "err", e)
		} else {
			stops = append(stops, cleanup)
			r.logger.Info("mesh subnet router enabled", "routes", routes)
		}
	}

	// Exit-node consumer: keep coord + relay on the physical link (else the
	// WireGuard transport would loop into the full tunnel).
	if r.cfg.ExitNode != "" {
		dp.SetExitBypassHosts([]string{r.cfg.Coord, r.cfg.Relay})
	}

	return &meshDataPlane{dp: dp, dns: dnsSink, key: priv, routes: routes, aliases: aliasRoutes, stop: func() {
		for i := len(stops) - 1; i >= 0; i-- {
			stops[i]()
		}
	}}, nil
}

// runControlPlane dials the coordinator and runs one session (enroll → watch
// netmap → apply) against the already-running data plane, returning when the
// stream ends or ctx is cancelled.
func (r *meshRunner) runControlPlane(ctx context.Context, data *meshDataPlane) error {
	// One session, one context. The loop's ctx outlives every session (it is the
	// daemon's), and this frame owns the coordinator connection that the session's
	// goroutines use. Cancelling here on the way out is what keeps a retry from
	// stacking a second set of them on top of the first. Controller.Run derives
	// its own as well; both layers are cheap.
	ctx, endSession := context.WithCancel(ctx)
	defer endSession()

	authKey := r.authKey()
	t, err := r.cfg.coordTrust(authKey)
	if err != nil {
		return fmt.Errorf("coordinator trust: %w", err)
	}
	conn, err := dialCoord(r.cfg.Coord, t)
	if err != nil {
		return fmt.Errorf("coordinator dial: %w", err)
	}
	defer conn.Close()

	name := r.cfg.Name
	if name == "" {
		name = defaultNodeName()
	}
	ctrl := &mesh.Controller{
		Coord:    mesh.NewCoordClient(conn),
		Datapath: data.dp,
		DNS:      data.dns,
		Reauth:   r.reauth,
		Tunnels:  r.tunnels,
		Params: mesh.RegisterParams{
			AuthKey:           authKey,
			NodeKey:           data.key.Public(),
			NodePrivate:       data.key,
			Name:              name,
			AdvertiseRoutes:   data.routes,
			AliasRoutes:       data.aliases,
			DeviceFingerprint: resolveFingerprint(r.logger),
			Services:          declaredServices(r.cfg.Services),
		},
		ExitNode:         r.cfg.ExitNode,
		HomePreference:   r.cfg.HomePreference,
		PinnedHomeRegion: r.cfg.PinnedHomeRegion,
		Routes:           r.routePolicy(),
		BlockIncoming:    r.cfg.BlockIncoming,
		Logger:           r.logger,
	}
	// Retained so the status endpoint can read the service self-check. Cleared
	// on the way out: a stale controller would keep serving the observations of
	// a session that has ended, which is worse than showing none.
	r.mu.Lock()
	r.ctrl = ctrl
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		if r.ctrl == ctrl {
			r.ctrl = nil
		}
		r.lastRegistered = ctrl.Registered()
		r.mu.Unlock()
	}()
	return ctrl.Run(ctx)
}

// checkCoordCert runs after a session ended without registering: it tells a
// coordinator that is down from one whose certificate this node's trust now
// refuses, which only a person can accept (they compare it with what
// `calabi-coord fingerprint` prints). The loop keeps retrying either way.
func (r *meshRunner) checkCoordCert(ctx context.Context) {
	if r.certs == nil || r.cfg.PlatformCoord {
		return
	}
	r.mu.Lock()
	registered := r.lastRegistered
	r.mu.Unlock()
	if registered {
		r.certs.clear()
		return
	}
	t, err := r.cfg.coordTrust(r.authKey())
	if err != nil || t.Mode == trust.Plaintext || t.Mode == trust.Platform {
		return
	}
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	presented := selfhosted.CertRefused(pctx, r.cfg.Coord, t, selfhosted.CoordALPN)
	if presented == "" {
		r.certs.clear()
		return
	}
	if was, _ := r.certs.get(); was != presented {
		r.logger.Warn("mesh: the coordinator presents a certificate this device does not trust; confirm it in the console",
			"coord", r.cfg.Coord, "presented", presented, "trust", t.Mode)
	}
	r.certs.set(presented, firstPin(t))
}

// coordCert is the certificate problem to show, if any: none while a session is
// registered, whatever an earlier attempt found.
func (r *meshRunner) coordCert() (presented, pinned string) {
	if r.certs == nil {
		return "", ""
	}
	r.mu.Lock()
	ctrl := r.ctrl
	r.mu.Unlock()
	if ctrl != nil && ctrl.Registered() {
		r.certs.clear()
		return "", ""
	}
	return r.certs.get()
}

// liveCoord is the running session's coordinator client once it has
// registered, else nil.
func (r *meshRunner) liveCoord() *mesh.CoordClient {
	r.mu.Lock()
	ctrl := r.ctrl
	r.mu.Unlock()
	if ctrl != nil && ctrl.Registered() {
		return ctrl.Coord
	}
	return nil
}

// declaredServices converts the config block into what the coordinator accepts.
// An empty proto means tcp — the common case, and the one people forget to type.
// Nothing is validated here: coord drops the unusable entries and keeps the rest,
// so a typo costs that line rather than the machine's enrollment.
func declaredServices(in []meshServiceDecl) []mesh.DeclaredService {
	out := make([]mesh.DeclaredService, 0, len(in))
	for _, s := range in {
		proto := s.Proto
		if proto == "" {
			proto = "tcp"
		}
		out = append(out, mesh.DeclaredService{Name: s.Name, Proto: proto, Port: s.Port, Target: s.Target, Note: s.Note})
	}
	return out
}

func (r *meshRunner) setDP(dp *mesh.WGDatapath) {
	r.mu.Lock()
	r.dp = dp
	r.mu.Unlock()
}

// datapath returns the live datapath, or nil while the mesh is down/retrying.
// Used by the status endpoint (added with /v1/mesh).
func (r *meshRunner) datapath() *mesh.WGDatapath {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dp
}

// ServiceObservations is the running session's last service self-check, or nil
// when the mesh is down.
func (r *meshRunner) ServiceObservations() []mesh.ServiceObservation {
	r.mu.Lock()
	ctrl := r.ctrl
	r.mu.Unlock()
	if ctrl == nil {
		return nil
	}
	return ctrl.ServiceObservations()
}

// UpdateDeclarations pushes revised declarations on the RUNNING session. Returns
// mesh.ErrNotEnrolled when there is no session to push on, which is the same
// answer the coordinator gives for an unknown node — so callers take one
// fallback path (re-enroll) for both.
func (r *meshRunner) UpdateDeclarations(ctx context.Context, services []mesh.DeclaredService, fingerprint string) error {
	r.mu.Lock()
	ctrl := r.ctrl
	r.mu.Unlock()
	if ctrl == nil {
		return mesh.ErrNotEnrolled
	}
	if err := ctrl.UpdateDeclarations(ctx, services, fingerprint); err != nil {
		return err
	}
	// Keep the runner's own config in step, so a session restart for some other
	// reason re-sends what the user last set rather than what the daemon booted
	// with.
	r.cfg.Services = toMeshServiceDecls(services)
	return nil
}

// toMeshServiceDecls is declaredServices' inverse, for writing an accepted
// update back into the runner's config.
func toMeshServiceDecls(in []mesh.DeclaredService) []meshServiceDecl {
	out := make([]meshServiceDecl, 0, len(in))
	for _, s := range in {
		out = append(out, meshServiceDecl{Name: s.Name, Proto: s.Proto, Port: s.Port, Target: s.Target, Note: s.Note})
	}
	return out
}

// Stop cancels the runner and waits for the loop to exit (closing the datapath).
// Safe to call when never started, and safe to call more than once (e.g. an API
// `mesh down` followed by the daemon's deferred Stop).
func (r *meshRunner) Stop() {
	r.mu.Lock()
	cancel, done, started := r.cancel, r.done, r.started
	r.mu.Unlock()
	if !started {
		return
	}
	cancel()
	<-done
}

// MeshStatus implements localweb.MeshSource: the node's mesh state for the
// :7400 console + `calabi mesh status`.
func (r *meshRunner) MeshStatus() localweb.MeshStatus {
	name := r.cfg.Name
	if name == "" {
		name = defaultNodeName()
	}
	ms := localweb.MeshStatus{Enabled: true, Coord: r.cfg.Coord, Relay: r.cfg.Relay, Name: name}
	// The home REGION (self-<org>-… = this org's own relay) — what tells the
	// overview a self-hosted relay from a platform one. Read from the controller,
	// which owns the measured home; Relay below is only the address.
	r.mu.Lock()
	ctrl := r.ctrl
	r.mu.Unlock()
	if ctrl != nil {
		ms.DerpHome = ctrl.HomeRegion()
	}
	if dp := r.datapath(); dp != nil {
		ms.Up = true
		snap := dp.Snapshot()
		ms.Overlay = snap.Overlay
		if snap.Relay != "" {
			ms.Relay = snap.Relay // the relay actually homed at, which may have moved
		}
		for _, a := range snap.SubnetAliases {
			ms.SubnetAliases = append(ms.SubnetAliases, localweb.MeshSubnetAlias{
				Alias: a.Alias.String(), Real: a.Real.String(),
			})
		}
		for _, a := range snap.UnaliasedRoutes {
			ms.UnaliasedRoutes = append(ms.UnaliasedRoutes, a.Real.String())
		}
		ms.AliasBudgetAddrs, ms.AliasUsedAddrs = snap.AliasBudgetAddrs, snap.AliasUsedAddrs
		ms.Datapath = localweb.MeshDatapath(snap.Datapath)
		// Peer NAMES come from the netmap, live state from WireGuard, and the
		// two meet here keyed by node key. The datapath deliberately knows
		// nothing about labels — it configures tunnels, and a label is not one
		// of its inputs.
		var facts map[string]mesh.PeerFacts
		if ctrl != nil {
			facts = ctrl.PeerFactsByKey()
		}
		for _, p := range snap.Peers {
			f := facts[p.PublicKey]
			var svcs []localweb.MeshPeerService
			for _, sv := range f.Services {
				svcs = append(svcs, localweb.MeshPeerService{
					Name: sv.Name, Proto: sv.Proto, Port: sv.Port,
				})
			}
			ms.Peers = append(ms.Peers, localweb.MeshPeer{
				PublicKey:        p.PublicKey,
				Name:             f.Name,
				Services:         svcs,
				OS:               f.OS,
				AllowedIPs:       p.AllowedIPs,
				LastHandshakeSec: p.LastHandshakeSec,
				RxBytes:          p.RxBytes,
				TxBytes:          p.TxBytes,
				Path:             p.Path,
				Endpoint:         p.Endpoint,
				RTTMicros:        p.RTTMicros,
				RelayRTTMicros:   p.RelayRTTMicros,
			})
		}
	}
	return ms
}

// MeshDown implements localweb.MeshSource: stop the mesh subsystem.
func (r *meshRunner) MeshDown() error {
	r.Stop()
	return nil
}

// --- consumer-side route policy (MESH.7 receiving end) ---------------------

// routePolicy resolves this node's stance on peers' advertised subnet routes.
// Excludes that don't parse are dropped with a warning rather than failing the
// session: a typo in an exclusion must not take the whole mesh down, and the
// safe reading of "I couldn't understand your exclusion" is to keep the rest of
// the policy working.
func (r *meshRunner) routePolicy() mesh.RoutePolicy {
	p := mesh.RoutePolicy{Accept: resolveAcceptRoutes(r.cfg.AcceptRoutes, r.cfg.KeyFile, r.logger)}
	for _, raw := range r.cfg.RouteExcludes {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		pfx, err := netip.ParsePrefix(raw)
		if err != nil {
			r.logger.Warn("mesh: ignoring an unparseable route exclusion", "value", raw, "err", err)
			continue
		}
		p.Excludes = append(p.Excludes, pfx.Masked())
	}
	return p
}

// resolveAcceptRoutes answers "does this node install peers' advertised subnet
// routes?", and REMEMBERS the answer the first time it has to guess.
//
// The default is OFF: a route lands in this machine's kernel routing table, and
// nobody but this machine can judge whether that breaks something local. But
// flipping the default under a node that is already USING subnet routes would
// silently cut traffic that works today — the same trap the coordinator's route
// approval avoided (core.Coordinator.Register: an unreviewed node keeps its
// routes "so the feature doesn't silently cut subnet routers that work today").
//
// So the first run decides by asking whether this node has meshed BEFORE: an
// existing WireGuard key means an upgrade, and an upgrade keeps working. A fresh
// node has no key yet and starts closed. The answer is written to creds
// immediately — sampling it again later would flip the default on the second
// boot, once the key exists.
//
// An explicit setting (config file or console) always wins and is never
// overwritten.
func resolveAcceptRoutes(explicit *bool, keyFile string, logger *slog.Logger) bool {
	if explicit != nil {
		return *explicit
	}
	cfg, err := creds.Load()
	if err == nil && cfg != nil && cfg.MeshAcceptRoutes != nil {
		return *cfg.MeshAcceptRoutes
	}
	if keyFile == "" {
		keyFile = defaultMeshKeyPath()
	}
	_, statErr := os.Stat(keyFile)
	seeded := statErr == nil // a key already on disk = this node has meshed before
	if seeded {
		logger.Info("mesh: keeping subnet-route acceptance ON for this already-enrolled device " +
			"(new devices now default to OFF; change it in the :7400 console under 组网 → 路由)")
	} else {
		logger.Info("mesh: subnet routes from peers are NOT installed by default; " +
			"enable it in the :7400 console under 组网 → 路由 if you need them")
	}
	if err == nil {
		if cfg == nil {
			cfg = &creds.Config{}
		}
		cfg.MeshAcceptRoutes = &seeded
		if serr := creds.Save(cfg); serr != nil {
			// Not fatal: the same decision is re-derived next boot from the same
			// signal. It only matters that we don't CHANGE the answer, and the key
			// file's existence is monotonic within a node's life.
			logger.Warn("mesh: could not persist the subnet-route default", "err", serr)
		}
	}
	return seeded
}

// meshMTUEnv overrides the tun MTU for BOTH daemon kinds.
//
// The YAML `mesh:` block only reaches the LOCAL daemon: the platform daemon
// builds its meshConfig in code (daemon_mesh_platform.go) and never fills MTU
// in, so a config-file knob is unreachable on every installed machine — which
// is the only kind that matters when someone is trying to diagnose a live
// network. An env var reaches both, and is settable where these daemons
// actually live: a systemd unit's Environment= and a launchd plist's
// EnvironmentVariables.
//
// It is a DIAGNOSTIC knob, not a setting: the default clears every path we know
// of, and lowering it is how a path-MTU black hole gets confirmed (WireGuard
// does no PMTU discovery of its own, so a link that silently eats full-size
// packets looks exactly like heavy random loss).
const meshMTUEnv = "CALABI_MESH_MTU"

// resolveMeshMTU picks the tun MTU: the env override, else the config field,
// else 0 (meaning mesh.DefaultMTU).
//
// Neither source fails hard. Both are STORED settings — a unit file, a plist, a
// YAML block — read long after they were written, by a service with no one
// watching. One unusable value must not cost the overlay address, every peer
// and every route; it costs itself, loudly (see the late-validation trap).
func resolveMeshMTU(fromConfig int, logger *slog.Logger) int {
	warn := func(src string, v int) {
		if logger != nil {
			logger.Warn("mesh: ignoring unusable mtu; using the default",
				"source", src, "mtu", v, "min", mesh.MinMTU, "max", mesh.MaxMTU, "using", mesh.DefaultMTU)
		}
	}
	if raw := strings.TrimSpace(os.Getenv(meshMTUEnv)); raw != "" {
		n, err := strconv.Atoi(raw)
		switch {
		case err != nil:
			warn(meshMTUEnv, 0)
		case !mesh.ValidMTU(n):
			warn(meshMTUEnv, n)
		default:
			if logger != nil {
				logger.Info("mesh: tun MTU overridden", "source", meshMTUEnv, "mtu", n)
			}
			return n
		}
	}
	if fromConfig != 0 && !mesh.ValidMTU(fromConfig) {
		warn("config", fromConfig)
		return 0
	}
	return fromConfig
}
