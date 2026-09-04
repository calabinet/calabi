package mesh

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// directTransport is implemented by datapaths that can carry WireGuard over the
// node's direct-path UDP socket (hole punching, MESH.4) as well as the relay.
// Optional: the Controller offers the transport to a datapath that accepts it and
// otherwise changes nothing.
type directTransport interface {
	attachDirect(ms *magicSock, paths pathFinder)
	detachDirect()
}

// sleepResumer is implemented by datapaths whose transport has to be rebuilt
// after the machine wakes from suspend: the relay links, whose sockets the far
// side forgot while this one was asleep. Optional — a datapath that doesn't
// implement it simply isn't told (the dry-run logger, the test fakes).
type sleepResumer interface {
	resumeFromSleep()
}

// DNSSink receives the name→overlay records derived from each netmap, so the
// MagicDNS resolver tracks the live topology. Optional (nil = no MagicDNS).
type DNSSink interface {
	SetRecords(map[string]netip.Addr)
}

// Controller drives the mesh subsystem's control-plane loop: enroll with the
// coordinator, watch the netmap, and push each update through to the datapath as
// a WGConfig. The relay client (derp.Client) is wired into the real datapath in
// the real-machine slice; this controller owns enroll + netmap → config.
//
// Reconnect/backoff on a dropped netmap stream lands with the daemon lifecycle
// wiring; Run returns the terminating error so the caller can retry.
type Controller struct {
	Coord    *CoordClient
	Datapath Datapath
	DNS      DNSSink // optional MagicDNS record sink
	Params   RegisterParams
	// ExitNode, if set, is the local exit-node selection (peer name or overlay
	// IP) whose default route this node adopts (MESH.7b). Resolved against each
	// netmap; the datapath installs the full-tunnel routes only for that peer.
	ExitNode string
	// HomePreference biases home-relay selection toward the org's own self-hosted
	// relays ("own") or the platform's ("platform"), mirroring the edge affinity
	// so switching "use my node" moves BOTH the edge egress and the mesh relay
	// home. Empty = no preference (pure latency — the default and the community
	// behavior). A soft preference: it never strands a node whose preferred class
	// has no reachable relay.
	HomePreference string
	// PinnedHomeRegion, when set, is the relay region this node homes on whenever
	// it answers a probe: the relay in the SAME facility as the edge the node's
	// tunnels are anchored to. It is what makes "switch my self-hosted node" move
	// the relay along with the edge instead of leaving it at whichever facility
	// measured fastest. Empty = pure latency within the preferred class.
	PinnedHomeRegion string
	// Routes is this node's stance on the subnet routes peers advertise. The zero
	// value refuses them all — callers resolve the user's setting and pass it in
	// explicitly, so "nobody wired it up" fails closed rather than quietly
	// installing whatever the mesh offers.
	Routes RoutePolicy
	Logger *slog.Logger

	// disco is the per-session DISCO private key generated in Run; its public half
	// rides registration (Params.DiscoKey) and the direct-path socket carries it
	// for the hole-punching exchange (MESH.4). Zero if generation failed.
	disco DiscoPrivateKey

	// netmapSelf holds what each netmap says about THIS node: its overlay
	// address, so the service self-check can dial the address peers use, and the
	// coordinator's registry of its services, which is the only way it learns
	// about ones a manager entered in the console (F3b/F4a).
	netmapSelf

	// healthGuard holds the last service self-check, so the machine's own :7400
	// console can show it without going through the control plane (F3b).
	healthGuard

	// paramsMu guards the MUTABLE half of Params — Services and
	// DeviceFingerprint, which UpdateDeclarations can revise mid-session so a
	// later re-registration sends the current values rather than the ones the
	// session happened to start with. Everything else in Params is fixed for the
	// session's lifetime and read without it.
	paramsMu sync.Mutex

	// stunMu guards stunServer, the resolved STUN endpoint (a relay's STUN port)
	// this node probes for its reflexive address. It's derived from the DERP map +
	// the node's home region on each netmap; zero until a usable one appears.
	stunMu     sync.Mutex
	stunServer netip.AddrPort

	// peersMu guards curPeers, the latest netmap's peers — the set the DISCO prober
	// re-pings on its periodic tick (between netmap pushes).
	peersMu  sync.Mutex
	curPeers []Peer

	// homeMu guards the home-relay selection (MESH.4 B2b): the DERP map from the
	// latest netmap, and the region this node measured as its closest relay. The
	// home is reported with every endpoint report; the coordinator distributes it
	// to peers as this node's derp_home.
	homeMu     sync.Mutex
	derpMap    DERPMap
	homeRegion string

	// reportEvery overrides endpointReportInterval when non-zero. Same-package
	// tests set it before Run so the loop can be watched in milliseconds; the
	// daemon never touches it. A field rather than a mutable package var, so
	// nothing writes it while a loop is reading it.
	reportEvery time.Duration
}

// reportInterval is the cadence endpointReportLoop actually runs at.
func (c *Controller) reportInterval() time.Duration {
	if c.reportEvery > 0 {
		return c.reportEvery
	}
	return endpointReportInterval
}

// endpointReportInterval re-reports candidate endpoints periodically so a roam
// (new Wi-Fi, VPN up/down, a fresh reflexive address) is picked up without waiting
// for a full reconnect.
const endpointReportInterval = 60 * time.Second

// dnsRecords maps each node in the netmap (self + peers) to its overlay IP for
// MagicDNS. Nameless or address-less entries are skipped.
func dnsRecords(nm NetMap) map[string]netip.Addr {
	recs := make(map[string]netip.Addr, len(nm.Peers)+1)
	add := func(name string, ip netip.Addr) {
		if name != "" && ip.IsValid() {
			recs[name] = ip
		}
	}
	add(nm.Self.Name, nm.Self.Overlay)
	for _, p := range nm.Peers {
		add(p.Name, p.Overlay)
	}
	return recs
}

// Run registers the node, then watches its netmap until ctx is cancelled or the
// stream ends, applying each netmap to the datapath.
func (c *Controller) Run(ctx context.Context) error {
	// Everything this session starts is bound to a context of its OWN, cancelled
	// when Run returns.
	//
	// The caller's ctx lives as long as the daemon and survives any number of
	// reconnects — the runner retries runOnce on the very same one. Binding the
	// loops below to it leaked a full set of goroutines per reconnect, each still
	// holding the closed coord connection and closed direct-path socket of a
	// session that had ended, re-reporting endpoints into them forever. The
	// symptom was several "report endpoints failed: the client connection is
	// closing" a minute, at as many distinct tick phases as there had been
	// reconnects, and it only cleared on a daemon restart.
	ctx, stopSession := context.WithCancel(ctx)
	defer stopSession()

	// Fresh DISCO keypair per session; its public half rides registration so peers
	// can authenticate this node's hole-punching probes (used from the probe slice).
	// Best-effort: a failure just leaves this session relay-only.
	if disco, err := GenerateDiscoKey(); err != nil {
		c.Logger.Warn("mesh: disco key generation failed; hole punching disabled this session", "err", err)
	} else {
		c.disco = disco
		c.Params.DiscoKey = disco.Public()
	}

	// registerParams, not c.Params: a mid-session UpdateDeclarations may have
	// revised the declarations, and a re-registration that sent the session's
	// original ones would quietly roll the user's edit back.
	reg, err := c.Coord.Register(ctx, c.registerParams())
	if err != nil {
		return fmt.Errorf("mesh: register: %w", err)
	}
	c.Logger.Info("mesh node registered", "node_id", reg.NodeID, "overlay", reg.Overlay)

	// Open the direct-path UDP socket and advertise our candidate endpoints so
	// peers can (from the probe slice on) reach us directly (MESH.4 B1/B2).
	// Best-effort: if the socket can't open, we log and keep working over the relay
	// — the existing relay datapath is untouched by this.
	var ms *magicSock
	var prober *discoProber
	if !c.disco.IsZero() {
		if s, err := newMagicSock(c.disco, c.Logger); err != nil {
			c.Logger.Warn("mesh: direct-path socket unavailable; relay-only this session", "err", err)
		} else {
			ms = s
			// Cancel BEFORE closing the socket the loops use: a loop that happened
			// to tick between the two would report a failure that is nothing but
			// this session shutting down. The Run-level defer above is idempotent;
			// this one only moves it earlier in the LIFO order.
			defer func() { stopSession(); ms.Close() }()
			// DISCO prober: ping peers' candidate endpoints and record which reach
			// them (MESH.4 B3).
			prober = newDiscoProber(ms, c.Logger)
			go prober.run(ctx, c.peers)
			// Hand the socket + prober to the datapath, so WireGuard traffic can
			// take a validated direct path instead of the relay (MESH.4 B3-3). A
			// datapath that doesn't support it (the dry-run logger, test fakes) just
			// isn't offered the transport and stays relay-only — as does this whole
			// session if the socket above failed to open.
			if dt, ok := c.Datapath.(directTransport); ok {
				dt.attachDirect(ms, prober)
				defer dt.detachDirect() // runs BEFORE ms.Close() above (defer is LIFO)
			}
			c.reportEndpoints(ctx, reg.NodeID, ms)       // initial (local only; no netmap yet)
			go c.endpointReportLoop(ctx, reg.NodeID, ms) // periodic re-report on roam
			go c.homeProbeLoop(ctx, reg.NodeID, ms)      // periodic re-measure of the closest relay
		}
	}

	// Self-check the declared services and report what this machine actually
	// observes (F3b). No-op when nothing is declared.
	go c.serviceHealthLoop(ctx, reg.NodeID)

	// Watch for the machine having been suspended. Every socket and NAT mapping
	// this session holds is invalid on the far side of a sleep, and none of the
	// loops above would notice for the better part of a minute.
	go c.wakeLoop(ctx, reg.NodeID, ms, prober)

	// Session-local: the refused set last logged. Owned by the callback below,
	// which Watch invokes sequentially, so it needs no lock.
	lastRefused := ""
	return c.Coord.Watch(ctx, reg.NodeID, func(nm NetMap) {
		c.setOverlay(nm.Self.Overlay)
		c.setSelfServices(nm.SelfServices)
		cfg := BuildWGConfig(nm)
		// Consumer-side route policy, applied before anything sees the config: a
		// refused prefix never reaches WireGuard's allowed-ips, so it can neither
		// be routed to nor sourced from. Logged only when the refused SET changes —
		// the coordinator re-pushes an unchanged netmap every 15 minutes, and a
		// standing policy decision is not news each time.
		cfg, refused := applyRoutePolicy(cfg, c.Routes)
		if fp := refusedFingerprint(refused); fp != lastRefused {
			lastRefused = fp
			for _, r := range refused {
				c.Logger.Info("mesh: not installing a peer's advertised subnet route",
					"route", r.Prefix.String(), "peer", r.Peer.String(), "reason", r.Reason)
			}
		}
		if c.ExitNode != "" {
			if cfg.ExitNode = ResolveExitNode(nm, c.ExitNode); cfg.ExitNode.IsZero() {
				c.Logger.Warn("mesh: exit node not found in netmap; routing directly until it appears", "exit_node", c.ExitNode)
			}
		}
		if err := c.Datapath.SetConfig(cfg); err != nil {
			c.Logger.Warn("mesh: datapath SetConfig failed", "err", err)
		}
		if c.DNS != nil {
			c.DNS.SetRecords(dnsRecords(nm))
		}
		// Relay selection (MESH.4 B2). The DERP map lists the fleet; the node's own
		// measurement decides which region is its home (B2b), and that region's STUN
		// endpoint is where it asks for its reflexive address. Until the first
		// measurement lands, fall back to the home the coordinator stamped, so a
		// single-relay deployment behaves exactly as before.
		if ms != nil {
			if c.setDERPMap(nm.DERP, nm.Self.DERPHome) {
				go c.homeProbe(ctx, reg.NodeID, ms)
			}
			if c.getStunServer() == (netip.AddrPort{}) {
				if hp, ok := stunHostPortFor(nm); ok {
					if sa, ok := resolveSTUNServer(ctx, hp); ok && c.setStunServer(sa) {
						go c.reportEndpoints(ctx, reg.NodeID, ms)
					}
				}
			}
		}
		// Probe peers' endpoints immediately on a fresh netmap (new peers / new
		// endpoints), in addition to the prober's periodic tick.
		if prober != nil {
			c.setPeers(nm.Peers)
			prober.Probe(nm.Peers)
		}
	})
}

func (c *Controller) setPeers(peers []Peer) {
	c.peersMu.Lock()
	c.curPeers = peers
	c.peersMu.Unlock()
}

// peers returns the latest netmap's peer set for the prober's periodic re-probe.
func (c *Controller) peers() []Peer {
	c.peersMu.Lock()
	defer c.peersMu.Unlock()
	return c.curPeers
}

// setDERPMap stores the latest relay directory and seeds the home region from the
// coordinator's stamp the first time (before this node has measured anything).
// Reports whether a (re)measurement is worth running: the map changed, or we have
// never measured one.
func (c *Controller) setDERPMap(m DERPMap, coordHome string) bool {
	c.homeMu.Lock()
	defer c.homeMu.Unlock()
	same := len(m.Regions) == len(c.derpMap.Regions)
	if same {
		for i := range m.Regions {
			if m.Regions[i].Code != c.derpMap.Regions[i].Code {
				same = false
				break
			}
		}
	}
	c.derpMap = m
	if c.homeRegion == "" {
		c.homeRegion = coordHome // the coordinator's default, until we measure
	}
	return !same && len(m.Regions) > 0
}

func (c *Controller) getDERPMap() DERPMap {
	c.homeMu.Lock()
	defer c.homeMu.Unlock()
	return c.derpMap
}

func (c *Controller) getHome() string {
	c.homeMu.Lock()
	defer c.homeMu.Unlock()
	return c.homeRegion
}

// HomeRegion is the relay region this node is currently homed on — the one the
// status surface shows as "中继节点". A "self-<org>-<label>" code means the org's
// own relay (the co-switch landed the node there); anything else is a platform
// region. Exported for the daemon's MeshStatus; safe before any measurement
// (returns the coordinator's default, or "").
func (c *Controller) HomeRegion() string { return c.getHome() }

// setHome records a newly measured home, returning true if it changed.
func (c *Controller) setHome(region string) bool {
	c.homeMu.Lock()
	defer c.homeMu.Unlock()
	if c.homeRegion == region {
		return false
	}
	c.homeRegion = region
	return true
}

// homeProbe measures every relay region and applies the outcome: the chosen home
// (reported to the coordinator, which hands it to peers as this node's derp_home)
// and that region's STUN endpoint, which is where this node then asks for the
// reflexive address it advertises. A changed home is reported immediately rather
// than at the next tick — peers should stop relaying via a far hop promptly.
func (c *Controller) homeProbe(ctx context.Context, nodeID int64, ms *magicSock) {
	m := c.getDERPMap()
	if len(m.Regions) == 0 || ctx.Err() != nil {
		return
	}
	measured := probeRegions(ctx, ms, m, c.Logger)
	if len(measured) == 0 {
		c.Logger.Warn("mesh: no relay region answered a latency probe; keeping the coordinator's home",
			"regions", len(m.Regions))
		return
	}
	cur := c.getHome()
	home := pickHome(cur, measured, c.homePref(), c.PinnedHomeRegion)
	if sa, ok := stunFor(home, measured); ok {
		c.setStunServer(sa)
	}
	if !c.setHome(home) {
		return
	}
	c.Logger.Info("mesh home relay selected by latency", "home_relay", home, "previous", cur,
		"rtt", rttOf(home, measured), "measured_regions", len(measured))
	c.reportEndpoints(ctx, nodeID, ms)
}

// homePref maps the daemon's edge-affinity string onto the home-selection bias,
// so "use my node" (own) homes on a self-hosted relay and "platform" avoids it.
// Anything else (the common case: no BYOI relay) is no preference — pure latency.
func (c *Controller) homePref() homePref {
	switch c.HomePreference {
	case "own":
		return homePreferOwn
	case "platform":
		return homePreferPlatform
	default:
		return homeAnyRelay
	}
}

// rttOf is the measured round trip of a region, for logging.
func rttOf(region string, measured []regionRTT) time.Duration {
	for _, m := range measured {
		if m.Region == region {
			return m.RTT
		}
	}
	return 0
}

// homeProbeLoop re-measures the fleet periodically so a node that moves (or whose
// path to its home degrades) re-homes without reconnecting.
func (c *Controller) homeProbeLoop(ctx context.Context, nodeID int64, ms *magicSock) {
	t := time.NewTicker(homeProbeInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.homeProbe(ctx, nodeID, ms)
		}
	}
}

// setStunServer stores the resolved STUN endpoint, returning true if it changed
// (so the caller re-probes only on a new server, not on every netmap).
func (c *Controller) setStunServer(sa netip.AddrPort) bool {
	c.stunMu.Lock()
	defer c.stunMu.Unlock()
	if c.stunServer == sa {
		return false
	}
	c.stunServer = sa
	return true
}

func (c *Controller) getStunServer() netip.AddrPort {
	c.stunMu.Lock()
	defer c.stunMu.Unlock()
	return c.stunServer
}

// reportEndpoints uploads the node's current candidate endpoints: its local
// interface addresses (B1) plus, when a STUN server is known, its reflexive
// (NAT-mapped) address (B2). Best-effort and quiet on a cancelled context.
func (c *Controller) reportEndpoints(ctx context.Context, nodeID int64, ms *magicSock) {
	if ctx.Err() != nil {
		return
	}
	eps := ms.Endpoints()
	if sa := c.getStunServer(); sa.IsValid() {
		if refl, err := ms.Reflexive(ctx, sa); err == nil && refl.IsValid() {
			eps = appendUniqueAddrPort(eps, refl)
		} else if err != nil && ctx.Err() == nil {
			c.Logger.Debug("mesh: reflexive-address probe failed", "stun", sa.String(), "err", err)
		}
	}
	if len(eps) == 0 {
		return
	}
	if err := c.Coord.ReportEndpoints(ctx, nodeID, eps, c.getHome()); err != nil {
		if ctx.Err() == nil {
			c.Logger.Warn("mesh: report endpoints failed", "err", err)
		}
		return
	}
	c.Logger.Info("mesh endpoints reported", "count", len(eps), "home_relay", c.getHome())
}

// stunHostPortFor returns the host:port of the STUN endpoint for the node's home
// DERP region, from the netmap's DERP map. ok=false if the node has no home, the
// region isn't in the map, or its relay advertises no STUN port. Pure.
func stunHostPortFor(nm NetMap) (string, bool) {
	home := nm.Self.DERPHome
	if home == "" {
		return "", false
	}
	for _, r := range nm.DERP.Regions {
		if r.Code != home {
			continue
		}
		for _, n := range r.Nodes {
			if n.HostName != "" && n.STUNPort > 0 {
				return net.JoinHostPort(n.HostName, strconv.Itoa(n.STUNPort)), true
			}
		}
	}
	return "", false
}

// resolveSTUNServer resolves a STUN host:port to a concrete UDP endpoint (literal
// IPs skip the resolver). ok=false on a bad host/port or a lookup failure.
func resolveSTUNServer(ctx context.Context, hostPort string) (netip.AddrPort, bool) {
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return netip.AddrPort{}, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return netip.AddrPort{}, false
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(ip.Unmap(), uint16(port)), true
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ips[0].Unmap(), uint16(port)), true
}

// appendUniqueAddrPort adds ap unless it's already present (the reflexive address
// can coincide with a local one when the node isn't behind a NAT).
func appendUniqueAddrPort(eps []netip.AddrPort, ap netip.AddrPort) []netip.AddrPort {
	for _, e := range eps {
		if e == ap {
			return eps
		}
	}
	return append(eps, ap)
}

const (
	// wakeCheckInterval is how often the wake detector looks for a gap in time.
	// Short, because the entire point is to react before the user does.
	wakeCheckInterval = 5 * time.Second
	// wakeGap is how much longer than one interval a tick has to be before the
	// machine counts as having been asleep rather than merely busy.
	wakeGap = 30 * time.Second
)

// wakeLoop watches for the machine having been suspended, and rebuilds what a
// suspend invalidates.
//
// Why a clock heuristic and not an OS power event: the symptom is the same on
// every platform (a laptop lid, Windows standby, a paused VM, a frozen
// container) and so is the recovery, so one portable detector is worth more than
// three platform-specific ones. BOTH clocks are read because neither is reliable
// on its own — whether a monotonic source keeps running across a suspend depends
// on the platform and the sleep state, and the wall clock is the one an NTP step
// can move.
//
// A false positive costs one relay re-dial and one endpoint report. That is the
// right way round: missing a real wake costs the user a meshnet that looks up
// and carries nothing.
func (c *Controller) wakeLoop(ctx context.Context, nodeID int64, ms *magicSock, prober *discoProber) {
	t := time.NewTicker(wakeCheckInterval)
	defer t.Stop()
	mono, wall := time.Now(), time.Now().Round(0)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		monoGap, wallGap := time.Since(mono), time.Now().Round(0).Sub(wall)
		if wokeUp(monoGap, wallGap) {
			c.Logger.Info("mesh: machine resumed from sleep; re-establishing the session",
				"gap", max(monoGap, wallGap).Round(time.Second).String())
			c.onWake(ctx, nodeID, ms, prober)
		}
		// Re-read AFTER the recovery, never before: onWake can take seconds, and
		// measuring the next gap from before it would report that work as a sleep.
		mono, wall = time.Now(), time.Now().Round(0)
	}
}

// wokeUp reads the two clock gaps between consecutive checks and says whether
// the machine was asleep. Either clock alone is enough: on some platforms and
// sleep states the monotonic source stops, on others it keeps running and only
// the wall clock shows the jump.
func wokeUp(monoGap, wallGap time.Duration) bool {
	return max(monoGap, wallGap) >= wakeCheckInterval+wakeGap
}

// onWake redoes the three things a suspend invalidated, in the order that gets
// the node carrying traffic soonest.
func (c *Controller) onWake(ctx context.Context, nodeID int64, ms *magicSock, prober *discoProber) {
	// The relay links first: they are what carries traffic while direct paths are
	// re-punched, and they are the ones that fail silently rather than loudly.
	if r, ok := c.Datapath.(sleepResumer); ok {
		r.resumeFromSleep()
	}
	if prober != nil {
		prober.Probe(c.peers()) // the NAT mapping behind every direct path is gone
	}
	if ms == nil || ctx.Err() != nil {
		return
	}
	// This node's reflexive address almost certainly changed, and until the
	// coordinator has the new one no peer can open a direct path back to it.
	c.reportEndpoints(ctx, nodeID, ms)
	c.homeProbe(ctx, nodeID, ms)
}

// endpointReportLoop re-reports endpoints on a fixed interval until ctx ends, so
// a network change is reflected without a reconnect.
func (c *Controller) endpointReportLoop(ctx context.Context, nodeID int64, ms *magicSock) {
	t := time.NewTicker(c.reportInterval())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.reportEndpoints(ctx, nodeID, ms)
		}
	}
}

// UpdateDeclarations pushes revised declarations to the coordinator on the
// RUNNING session, and remembers them so a later re-registration sends the same
// thing.
//
// This is the cheap path for an edit that changes no addresses: what the node
// offers. The expensive path — stop the session, enroll again — reconfigures
// WireGuard, re-dials every relay and re-punches every direct path, which is
// what a service edit used to cost.
//
// ErrNotEnrolled means the coordinator has no such node (or predates this RPC);
// the caller re-enrolls instead.
func (c *Controller) UpdateDeclarations(ctx context.Context, services []DeclaredService, fingerprint string) error {
	c.paramsMu.Lock()
	p := c.Params
	c.paramsMu.Unlock()
	p.Services = services
	if fingerprint != "" {
		p.DeviceFingerprint = fingerprint
	}
	if c.Coord == nil {
		return ErrNotEnrolled
	}
	if err := c.Coord.UpdateDeclarations(ctx, p); err != nil {
		return err
	}
	c.paramsMu.Lock()
	c.Params.Services = services
	if fingerprint != "" {
		c.Params.DeviceFingerprint = fingerprint
	}
	c.paramsMu.Unlock()
	if c.Logger != nil {
		c.Logger.Info("mesh declarations updated without re-enrolling", "services", len(services))
	}
	return nil
}

// registerParams returns the params a (re)registration should send, including
// any revision UpdateDeclarations recorded since the session started.
func (c *Controller) registerParams() RegisterParams {
	c.paramsMu.Lock()
	defer c.paramsMu.Unlock()
	return c.Params
}
