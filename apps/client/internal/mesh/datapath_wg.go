package mesh

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// wgMTU is a conservative tunnel MTU that leaves room for the WireGuard + relay
// framing overhead over most paths.
const wgMTU = 1280

// tunName is the requested mesh interface name; it is platform-specific because
// macOS only accepts "utun"/"utunN" (see tunname_*.go). The OS may still adjust
// it — the authoritative name comes from tunDev.Name().

// meshOverlayCIDR is the overlay CGNAT range (100.64.0.0/10, matching calabi-coord
// IPAM). configureLink routes it at the tun so overlay traffic enters WireGuard.
const meshOverlayCIDR = "100.64.0.0/10"

// errLinkConfigManual is returned by configureLink on platforms where the tun
// address/route step isn't automated yet; SetConfig degrades it to a warning
// (the WG device is already up) so the operator can configure the link by hand.
var errLinkConfigManual = errors.New("mesh: automatic tun link configuration is not supported on this platform")

// WGDatapath is the REAL Datapath: a wireguard-go device on a tun interface whose
// transport is meshBind — the calabi-derp relay, upgraded to a direct UDP path
// per peer wherever hole punching finds one. It requires a tun device and
// elevated privileges (wintun.dll on Windows), so it can only run on a real
// machine — NOT in CI.
//
// ⚠ COMPILE-VERIFIED ONLY. Written against wireguard-go's real API; the runtime
// packet path + the OS-level tun address/route step (see SetConfig TODO) need a
// two-machine ping-over-DERP run to validate.
type WGDatapath struct {
	priv   PrivateKey
	self   meshproto.NodeKey
	ifname string
	tun    tun.Device
	dev    *device.Device
	bind   *meshBind
	relays *relayPool
	// filter drops inbound packets the meshnet's access rules don't allow
	// (MESH.5b). Installed on the tun; updated from every netmap.
	filter *PacketFilter
	uapi   net.Listener // WireGuard UAPI socket (for `wg show`); nil off Linux
	logger *slog.Logger

	// curOverlay is the address last applied to the tun link, so SetConfig only
	// (re)runs the OS address/route step when the node's overlay IP changes.
	// Guarded by statMu (written on SetConfig's goroutine, read by Snapshot).
	statMu     sync.Mutex
	curOverlay netip.Addr

	// lastPeerConf is the canonical UAPI peer string last written to the device.
	// SetConfig compares against it and skips the write — and its replace_peers
	// reset — when a netmap re-push carries an identical peer set. That is MOST
	// pushes: the coordinator re-sends each node's netmap on a 15-min grant-refresh
	// timer and on every endpoint/home report (several times a minute), and none of
	// those change the peers. SetConfig goroutine only.
	lastPeerConf string

	// curSubnets are the subnet-router prefixes this datapath currently has an OS
	// route installed for. Every apply diffs the netmap's selection against it
	// (diffSubnetRoutes) so a CIDR a peer STOPPED advertising loses its route
	// instead of blackholing traffic to it. SetConfig goroutine only.
	curSubnets []netip.Prefix

	// Exit-node (MESH.7b) state, all touched only on SetConfig's goroutine.
	// bypassHosts are the control-plane endpoints (coord + relay, host:port) that
	// MUST keep flowing over the physical link when a full-tunnel exit node is
	// selected — otherwise WireGuard's own transport to the relay would loop back
	// into the tun. curExit is the exit peer whose split-default routes are
	// currently installed; exitCleanup removes them.
	bypassHosts []string
	curExit     meshproto.NodeKey
	exitCleanup func()
}

// SetExitBypassHosts records the control-plane endpoints (coord + relay,
// host:port) to pin to the physical link while an exit node carries the default
// route. Call once before the datapath runs, from the layer that knows both
// addresses (the daemon / `mesh up`). No-op for nodes that never use an exit node.
func (d *WGDatapath) SetExitBypassHosts(hosts []string) {
	d.bypassHosts = hosts
}

func (d *WGDatapath) setOverlay(a netip.Addr) {
	d.statMu.Lock()
	d.curOverlay = a
	d.statMu.Unlock()
}

func (d *WGDatapath) overlay() netip.Addr {
	d.statMu.Lock()
	defer d.statMu.Unlock()
	return d.curOverlay
}

// Snapshot reports the datapath's live state (overlay + per-peer WireGuard
// stats) for `calabi mesh status` and the :7400 console. Safe to call from any
// goroutine.
func (d *WGDatapath) Snapshot() Status {
	st := Status{Relay: d.relays.Home()}
	if o := d.overlay(); o.IsValid() {
		st.Overlay = o.String()
	}
	if dump, err := d.dev.IpcGet(); err == nil {
		st.Peers = parseUAPI(dump)
		d.annotatePaths(st.Peers)
		sortPeersByOverlay(st.Peers)
	}
	return st
}

// sortPeersByOverlay puts the peer list in a STABLE, human-readable order:
// ascending overlay IP (100.64.0.4 before 100.64.0.5). WireGuard's IpcGet dumps
// peers in an internal order that reshuffles — especially right after a
// replace_peers re-add — which made the console's peer table jump around on
// every poll. A peer with no overlay address (shouldn't happen) sorts last, by
// node key, so the order is always total and deterministic.
func sortPeersByOverlay(peers []PeerStatus) {
	overlayPfx := netip.MustParsePrefix(meshOverlayCIDR)
	overlayOf := func(p PeerStatus) (netip.Addr, bool) {
		for _, s := range p.AllowedIPs {
			if px, err := netip.ParsePrefix(s); err == nil && overlayPfx.Contains(px.Addr()) {
				return px.Addr(), true
			}
		}
		return netip.Addr{}, false
	}
	sort.SliceStable(peers, func(i, j int) bool {
		ai, aok := overlayOf(peers[i])
		aj, bok := overlayOf(peers[j])
		switch {
		case aok && bok && ai != aj:
			return ai.Less(aj)
		case aok != bok:
			return aok // a peer with an overlay IP sorts before one without
		default:
			return peers[i].PublicKey < peers[j].PublicKey
		}
	})
}

// annotatePaths fills in each peer's live transport — the direct endpoint hole
// punching found, or the relay. Purely reported state: it re-reads exactly what
// the bind's Send would choose right now.
func (d *WGDatapath) annotatePaths(peers []PeerStatus) {
	home := d.relays.Home()
	for i := range peers {
		peers[i].Path = PathRelay
		key, err := meshproto.ParseNodeKey(peers[i].PublicKey)
		if err != nil {
			continue
		}
		// Relayed: show WHICH relay carries it — with a fleet that is the peer's own
		// home relay, not necessarily ours.
		if relay := d.bind.relayFor(key); relay != "" {
			peers[i].Endpoint = relay
		} else {
			peers[i].Endpoint = home
		}
		if ap, ok := d.bind.directPath(key); ok {
			peers[i].Path = PathDirect
			peers[i].Endpoint = ap.String()
			if rtt, ok := d.bind.directRTT(key); ok {
				peers[i].RTTMicros = rtt.Microseconds()
			}
		}
	}
}

// The Controller finds this datapath by the directTransport interface, so a
// signature drift would silently leave every session relay-only — fail the build
// instead.
var _ directTransport = (*WGDatapath)(nil)

// attachDirect wires the hole-punching transport (the shared DISCO/WireGuard UDP
// socket + the prober that validates paths over it) into the running datapath.
// The control-plane loop owns both — they exist only once a session is up — so
// this is a seam, not a constructor argument: a datapath with nothing attached is
// exactly the relay-only datapath that shipped in MESH.2.
func (d *WGDatapath) attachDirect(ms *magicSock, paths pathFinder) {
	d.bind.attachDirect(ms, paths)
	d.logger.Info("mesh direct transport attached (hole punching active)", "port", ms.LocalPort())
}

// detachDirect drops the direct transport again (the socket is closing with the
// control-plane session); traffic returns to the relay.
func (d *WGDatapath) detachDirect() {
	d.bind.detachDirect()
}

// NewWGDatapath brings up the tun + WireGuard device + relay transport. relayAddr
// is the calabi-derp endpoint (host:port) this node uses as its DERP home.
func NewWGDatapath(priv PrivateKey, relayAddr string, logger *slog.Logger) (*WGDatapath, error) {
	self := priv.Public()

	// On Windows, stage + pre-load the bundled wintun.dll so CreateTUN finds the
	// driver without the user having to place the DLL by hand. Best-effort: no-op
	// off Windows, and a failure falls back to a system-installed wintun.dll.
	if err := ensureWintun(logger); err != nil {
		return nil, err
	}
	tunDev, err := tun.CreateTUN(tunName, wgMTU)
	if err != nil {
		return nil, fmt.Errorf("mesh: create tun (needs privileges / wintun): %w", err)
	}
	// The OS may adjust the requested name; the authoritative one drives the
	// address/route step in SetConfig.
	ifname, err := tunDev.Name()
	if err != nil {
		_ = tunDev.Close()
		return nil, fmt.Errorf("mesh: tun name: %w", err)
	}

	bind := newMeshBind(self, logger)
	// The relay pool starts as the single bootstrap link this node was configured
	// with; once the netmap arrives it also links to the relays its peers are homed
	// at (MESH.4 B2b). Every link feeds the same inbound queue.
	relays := newRelayPool(self, [meshproto.KeyLen]byte(priv), func(src meshproto.NodeKey, ct []byte) {
		bind.deliver(src, ct)
	}, logger)
	if err := relays.DialHome(context.Background(), relayAddr); err != nil {
		// Not fatal any more. Hole punching (MESH.4) means a node without a relay
		// link is degraded, not unreachable; and under R0' a relay that requires
		// authorization will refuse this very first dial, because the grant only
		// arrives with the netmap moments later. The send path re-dials the home
		// address on its own, by which point SetConfig has supplied the grant.
		logger.Warn("mesh: home relay not up yet; will re-dial (direct paths unaffected)", "relay", relayAddr, "err", err)
	}
	bind.attach(relays)

	// Wrap the tun so inbound packets pass the node's access rules before they
	// reach the OS. Until a netmap arrives the filter is disabled (= pass-through),
	// so this changes nothing for a coordinator that doesn't compile filters.
	filter := &PacketFilter{}
	dev := device.NewDevice(newFilteredTUN(tunDev, filter, logger), bind, device.NewLogger(wgLogLevel(), "calabi-mesh: "))
	if err := dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=0\n", priv.Hex())); err != nil {
		dev.Close()
		_ = relays.Close()
		return nil, fmt.Errorf("mesh: set private key: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		_ = relays.Close()
		return nil, fmt.Errorf("mesh: device up: %w", err)
	}

	// Expose the WireGuard UAPI socket (/var/run/wireguard/<ifname>.sock) so the
	// standard `wg` tool can introspect this in-process device out-of-process —
	// `mesh up` runs in the foreground, so operators query handshake/transfer
	// state from another shell (`wg show <ifname>`). Best-effort: on failure (or
	// off Linux, where openUAPI is a no-op) the datapath still works, only `wg`
	// introspection is unavailable.
	var uapiLn net.Listener
	if ln, err := openUAPI(ifname); err != nil {
		logger.Warn("mesh: UAPI socket unavailable (`wg show` won't work)", "ifname", ifname, "err", err)
	} else if ln != nil {
		uapiLn = ln
		go serveUAPI(ln, dev, logger)
	}

	return &WGDatapath{priv: priv, self: self, ifname: ifname, tun: tunDev, dev: dev, bind: bind, relays: relays, filter: filter, uapi: uapiLn, logger: logger}, nil
}

// wgLogLevel maps CALABI_MESH_WG_LOG to a wireguard-go device log level.
// Default is Error (quiet); "verbose"/"debug" surfaces the full handshake +
// routing trace for debugging the relay datapath.
func wgLogLevel() int {
	switch os.Getenv("CALABI_MESH_WG_LOG") {
	case "verbose", "debug":
		return device.LogLevelVerbose
	case "silent", "off":
		return device.LogLevelSilent
	default:
		return device.LogLevelError
	}
}

// serveUAPI accepts wg control connections and hands each to the device's UAPI
// handler until the listener is closed.
func serveUAPI(ln net.Listener, dev *device.Device, logger *slog.Logger) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed on shutdown
		}
		go dev.IpcHandle(conn)
	}
}

// SetConfig applies the peer set via the WireGuard UAPI, then (on the first
// apply / whenever the overlay IP changes) assigns the node's overlay /32 to the
// tun and routes meshOverlayCIDR at it via configureLink. Idempotent
// (replace_peers=true rewrites the full set each call; link config is guarded by
// curOverlay).
//
// The link step is automated on Linux (iproute2); on other platforms
// configureLink returns errLinkConfigManual and we warn once with the exact
// address/route the operator must set by hand — see linkconfig_*.go.
func (d *WGDatapath) SetConfig(cfg WGConfig) error {
	// Give the bind its per-peer routing tables BEFORE the peers go live, so the
	// first direct packet from a newly-added peer is already attributable and the
	// first relayed one already takes that peer's own relay.
	d.bind.setPeers(cfg)
	// Access rules for INBOUND traffic. Applied before the peers go live so a
	// packet can't slip in during the window between the two.
	if d.filter.SetRules(cfg.FilterEnabled, cfg.Filter) {
		d.logger.Info("mesh access rules applied (inbound)",
			"enforcing", cfg.FilterEnabled, "rules", len(cfg.Filter))
	}
	// Keep the relay links aligned with the map: our own home relay (where peers
	// reach us) plus a warm link to every relay a peer is homed at (MESH.4 B2b).
	// Before Reconcile: the dials it starts must already carry the current
	// authorization, or a relay that requires one would reject them.
	d.relays.SetGrant(cfg.RelayGrant)
	d.relays.Reconcile(cfg.SelfRelay, peerRelayAddrs(cfg))

	// Build the UAPI peer string from a key-sorted copy so it is CANONICAL: the
	// coordinator doesn't guarantee a stable peer order across pushes, and an
	// order-only difference must not read as a change. WireGuard is order-
	// independent, so sorting the applied set is harmless.
	sorted := append([]WGPeer(nil), cfg.Peers...)
	sort.Slice(sorted, func(i, j int) bool {
		return bytes.Compare(sorted[i].PublicKey[:], sorted[j].PublicKey[:]) < 0
	})
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", d.priv.Hex())
	b.WriteString("replace_peers=true\n")
	isExit := func(k meshproto.NodeKey) bool { return !cfg.ExitNode.IsZero() && cfg.ExitNode.Equal(k) }
	for _, p := range sorted {
		fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(p.PublicKey[:]))
		// The endpoint names the PEER, not an address: the node key, which
		// meshBind.ParseEndpoint decodes back. The bind then picks the transport per
		// packet (direct when hole punching validated a path, else the relay), so a
		// path change never needs a config rewrite.
		fmt.Fprintf(&b, "endpoint=%s\n", p.PublicKey.String())
		for _, aip := range p.AllowedIPs {
			// A default route (0.0.0.0/0 // ::/0) is the exit-node signal. Give it to
			// WireGuard ONLY for the peer this node picked as its exit node; otherwise
			// merely advertising an exit node would hijack every other node's default
			// route. Overlay /32s and subnet-router CIDRs are unaffected.
			if isDefaultRoute(aip) && !isExit(p.PublicKey) {
				continue
			}
			fmt.Fprintf(&b, "allowed_ip=%s\n", aip.String())
		}
		if p.PersistentKeepalive > 0 {
			fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", int(p.PersistentKeepalive.Seconds()))
		}
	}
	// Only touch WireGuard when the peer set actually changed. replace_peers=true
	// tears down and re-adds every peer, ZEROING each peer's rx/tx counters and
	// forcing a fresh handshake — so re-applying an identical set on every grant-
	// refresh / endpoint-report netmap (several times a minute) makes the live peer
	// view reset for nothing. The grant refresh itself already ran above via
	// relays.SetGrant, independent of this write.
	peerConf := b.String()
	peersChanged := peerConf != d.lastPeerConf
	if peersChanged {
		if err := d.dev.IpcSet(peerConf); err != nil {
			return fmt.Errorf("mesh: apply peers: %w", err)
		}
		d.lastPeerConf = peerConf
		d.logger.Info("mesh WG peers applied", "peers", len(cfg.Peers), "overlay", cfg.OverlayAddr)
	}

	// Assign the overlay address + route once (or when it changes) so the kernel
	// actually delivers overlay traffic into the tun. Without this the peers are
	// configured but no packets ever reach WireGuard.
	if cfg.OverlayAddr.IsValid() && cfg.OverlayAddr != d.overlay() {
		switch err := configureLink(d.tunLUID(), d.ifname, cfg.OverlayAddr); {
		case err == nil:
			d.logger.Info("mesh tun link configured", "ifname", d.ifname, "overlay", cfg.OverlayAddr, "route", meshOverlayCIDR)
			d.setOverlay(cfg.OverlayAddr)
		case errors.Is(err, errLinkConfigManual):
			d.logger.Warn("mesh: configure the tun link manually", "hint", err.Error())
			d.setOverlay(cfg.OverlayAddr) // warn once, not on every netmap update
		default:
			return fmt.Errorf("mesh: configure link: %w", err)
		}
	}

	// MESH.7a: a subnet-router peer's advertised CIDRs arrive as allowed-ips
	// outside the overlay range; add an OS route for each at the tun so
	// overlay-external destinations flow into WireGuard. Default routes are
	// handled separately (exit node, below) — never as a plain tun route. An
	// advertised subnet IDENTICAL to a local directly-connected network is dropped
	// (local wins) so it can't hijack the machine's own LAN; more-specific/broader
	// overlaps are kept — longest-prefix match resolves them safely.
	overlayPfx := netip.MustParsePrefix(meshOverlayCIDR)
	locals, err := localDirectSubnets(d.ifname)
	if err != nil {
		d.logger.Warn("mesh: enumerate local subnets failed; advertised routes not filtered against local networks", "err", err)
	}
	extra, dropped := selectSubnetRoutes(cfg.Peers, overlayPfx, locals)
	for _, dr := range dropped {
		d.logger.Warn("mesh: advertised subnet is identical to a local network; not routing into mesh (local wins — reach the remote copy via address translation)",
			"advertised", dr.Advertised, "local", dr.Local, "peer", dr.Peer.String())
	}
	// Diff against what we installed last time instead of re-adding the whole
	// selection: new prefixes get a route, VANISHED ones get theirs removed. The
	// diff also subsumes the old peersChanged gate — an unchanged peer set diffs to
	// empty, so a no-op netmap makes no OS call and logs nothing on its own. That
	// gate was in fact part of the bug: it also carried `len(extra) > 0`, so the
	// one case that most needs a withdrawal — a peer that stopped advertising
	// EVERYTHING — skipped the block entirely.
	add, del := diffSubnetRoutes(d.curSubnets, extra)
	addOK, delOK := true, true
	// Withdraw before adding: the peer write above has already removed these from
	// allowed-ips, so every moment the route still points at the tun is a moment
	// that subnet is blackholed rather than falling back to the physical link.
	if len(del) > 0 {
		if err := delSubnetRoutes(d.tunLUID(), d.ifname, del); err != nil {
			delOK = false
			d.logger.Warn("mesh: withdraw subnet routes failed; those subnets stay blackholed until a later netmap retries",
				"routes", del, "err", err)
		} else {
			d.logger.Info("mesh subnet routes withdrawn", "routes", del)
		}
	}
	if len(add) > 0 {
		if err := addSubnetRoutes(d.tunLUID(), d.ifname, add); err != nil {
			addOK = false
			d.logger.Warn("mesh: add subnet routes failed", "routes", add, "err", err)
		} else {
			d.logger.Info("mesh subnet routes applied", "routes", add)
		}
	}
	d.curSubnets = nextSubnetState(extra, add, del, addOK, delOK)

	d.applyExitNode(cfg.ExitNode)
	return nil
}

// peerRelayAddrs is the set of relay addresses this node's peers are homed at —
// the links the pool should hold so a relayed packet reaches a peer on its own
// relay. Deduplicated; peers with no resolvable home are skipped (they fall back
// to this node's home relay).
func peerRelayAddrs(cfg WGConfig) []string {
	seen := make(map[string]bool, len(cfg.Peers))
	var out []string
	for _, p := range cfg.Peers {
		addr := cfg.RelayByRegion[p.DERPHome]
		if addr == "" || seen[addr] {
			continue
		}
		seen[addr] = true
		out = append(out, addr)
	}
	return out
}

// isDefaultRoute reports whether pfx is the IPv4/IPv6 default route — the
// wire signal that a peer advertises itself as an exit node.
func isDefaultRoute(pfx netip.Prefix) bool { return pfx.Bits() == 0 }

// applyExitNode reconciles the OS-level full-tunnel routes with the selected
// exit peer. It only re-touches the routing table when the selection changes:
// on a switch it tears down the previous exit's split-default + bypass routes,
// then (if a valid exit is selected) pins the control-plane endpoints to the
// physical link and routes 0.0.0.0/1 + 128.0.0.0/1 at the tun so every non-mesh
// destination flows to the exit peer. Selecting the zero key removes them.
// Best-effort: a failure is logged, not fatal (the mesh itself still works).
func (d *WGDatapath) applyExitNode(sel meshproto.NodeKey) {
	if sel.Equal(d.curExit) {
		return
	}
	if d.exitCleanup != nil { // switching away from a previous exit node
		d.exitCleanup()
		d.exitCleanup = nil
	}
	d.curExit = sel
	if sel.IsZero() {
		d.bind.setDirectEnabled(true) // no full tunnel: direct paths are safe again
		if d.overlay().IsValid() {    // only log the transition once we were actually up
			d.logger.Info("mesh exit node cleared; default route restored to physical link")
		}
		return
	}
	// Every relay link must stay on the physical path, not just the bootstrap one:
	// with a fleet, this node holds links to its peers' relays too.
	bypass, err := resolveBypass(append(append([]string(nil), d.bypassHosts...), d.relays.Addrs()...))
	if err != nil {
		d.logger.Warn("mesh: exit node selected but control-plane bypass unresolved; not full-tunneling (would loop)", "err", err)
		d.curExit = meshproto.NodeKey{} // force a retry on the next netmap
		return
	}
	// privateV4Blocks stay on the physical link (MESH.7b "allow LAN access") so
	// full-tunnelling never cuts off the local network — directly-connected AND
	// one-hop-via-gateway private destinations. More-specific subnet-router routes
	// still win over these /8–/16 carves, so mesh-reachable remote subnets keep
	// working. Passed as lanKeep; the per-OS impl pins each to its physical nexthop.
	cleanup, err := enableExitRoutes(d.tunLUID(), d.ifname, bypass, privateV4Blocks)
	if err != nil {
		d.logger.Warn("mesh: enable exit-node routes failed", "err", err)
		d.curExit = meshproto.NodeKey{}
		return
	}
	d.exitCleanup = cleanup
	// A full tunnel captures every destination not explicitly bypassed — including
	// a peer's public IP. WireGuard's own transport must NOT be captured (it would
	// loop back through the tun), and only the relay is on the bypass list, so
	// direct paths stand down for as long as the exit node is engaged.
	d.bind.setDirectEnabled(false)
	d.logger.Info("mesh exit node engaged (full tunnel; direct paths paused, relay only)",
		"exit_node", sel.String(), "bypass", d.bypassHosts, "lan_keep", privateV4Blocks)
}

// Close tears down the exit-node routes (restoring the physical default route),
// the UAPI socket, the device (which closes the bind + tun) and the relay link.
// resumeFromSleep implements sleepResumer: rebuild the relay transport after the
// machine wakes. Only the relay links need it — the tun device and the WireGuard
// state survive a suspend, and the direct paths re-punch themselves once the
// prober runs.
func (d *WGDatapath) resumeFromSleep() {
	d.relays.ResetLinks()
}

func (d *WGDatapath) Close() error {
	if d.exitCleanup != nil {
		d.exitCleanup()
		d.exitCleanup = nil
	}
	if d.uapi != nil {
		_ = d.uapi.Close()
	}
	if d.dev != nil {
		d.dev.Close()
	}
	if d.relays != nil {
		_ = d.relays.Close()
	}
	return nil
}
