package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/calabi/calabi/apps/client/internal/creds"
	"github.com/calabi/calabi/apps/client/internal/mesh"
	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// runMesh is the `calabi mesh` command group — the WireGuard mesh
// subsystem. Available in BOTH deployments (mesh is the open data plane).
//
// ⚠ `mesh up` needs a tun device + privileges (wintun.dll on Windows) and has
// NOT been validated end to end — MESH.2.
// It's wired for the two-machine ping-over-DERP acceptance, run on real hosts.
func runMesh(args []string) int {
	if len(args) == 0 {
		printMeshUsage()
		return 2
	}
	switch args[0] {
	case "up":
		return runMeshUp(args[1:])
	case "status":
		return runMeshStatus(args[1:])
	case "down":
		return runMeshDown(args[1:])
	case "relaytest":
		return runMeshRelayTest(args[1:])
	case "help", "-h", "--help":
		printMeshUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "calabi mesh: unknown subcommand %q\n", args[0])
		printMeshUsage()
		return 2
	}
}

func runMeshUp(args []string) int {
	fs := flag.NewFlagSet("mesh up", flag.ContinueOnError)
	coordAddr := fs.String("coord", "", "coordinator address host:port (in production: your bff-console entrypoint)")
	relayAddr := fs.String("relay", "", "relay address host:port (this device's DERP home)")
	authKey := fs.String("auth-key", "", "tk_ auth key (platform) or pre-shared key (self-hosted)")
	name := fs.String("name", defaultNodeName(), "device name (how this machine is labelled in the console)")
	mtu := fs.Int("mtu", mesh.DefaultMTU, "tun MTU (576-1500); LOWER it to test a path that black-holes full-size packets")
	keyFile := fs.String("key-file", defaultMeshKeyPath(), "path to this device's WireGuard private key (created if absent)")
	magicDNS := fs.Bool("magic-dns", false, "resolve mesh device names by REWRITING this machine's /etc/resolv.conf (Linux only; off by default — an ungraceful exit leaves the host with no DNS)")
	advertise := fs.String("advertise-routes", "", "comma-separated subnets to advertise as a subnet router, /24 or smaller (e.g. 192.168.1.0/24). A bare address is a single host: 192.168.1.22")
	aliasRoutes := fs.String("alias-routes", "", "DEPRECATED and ignored: every advertised route is aliased where the host supports it")
	advertiseExit := fs.Bool("advertise-exit-node", false, "advertise this device as an exit device (offer to forward peers' default route to the internet)")
	exitNode := fs.String("exit-node", "", "route this device's default traffic through the named exit device (name or overlay IP)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *coordAddr == "" || *relayAddr == "" || *authKey == "" {
		fmt.Fprintln(os.Stderr, "calabi mesh up: --coord, --relay and --auth-key are required")
		printMeshUsage()
		return 2
	}
	routes, err := parseCIDRList(*advertise)
	if err != nil {
		fmt.Fprintf(os.Stderr, "calabi mesh up: --advertise-routes: %v\n", err)
		return 2
	}
	// Which of them to publish under a stand-in prefix. Parsed but not checked
	// against `routes`: the coordinator grants an alias only for a route it also
	// approved, so a stray entry is inert rather than fatal.
	aliased, err := parseCIDRList(*aliasRoutes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "calabi mesh up: --alias-routes: %v\n", err)
		return 2
	}
	if *advertiseExit {
		routes = append(routes, netip.PrefixFrom(netip.IPv4Unspecified(), 0)) // 0.0.0.0/0
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	priv, err := mesh.LoadOrCreateKey(*keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "calabi mesh up: key: %v\n", err)
		return 1
	}
	logger.Info("mesh identity", "node_key", priv.Public(), "key_file", *keyFile)

	// Bring up the WireGuard tun datapath over the relay. This is the step that
	// needs a tun device + privileges.
	// Typed on the command line, so a bad value fails here rather than being
	// quietly ignored — the person who just typed it is present to fix it.
	if !mesh.ValidMTU(*mtu) {
		fmt.Fprintf(os.Stderr, "calabi mesh up: --mtu %d is outside %d..%d\n", *mtu, mesh.MinMTU, mesh.MaxMTU)
		return 1
	}
	dp, err := mesh.NewWGDatapath(priv, *relayAddr, *mtu, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "calabi mesh up: datapath: %v\n", err)
		return 1
	}
	defer dp.Close()

	// MagicDNS: resolve peer names to overlay IPs. Opt-in, because the cost of
	// having it on is paid by the whole machine and not just the mesh — it takes
	// over /etc/resolv.conf, and an ungraceful exit leaves nothing listening on
	// the address it wrote there. Best-effort even when asked for: mesh works
	// without it (e.g. on platforms whose OS integration isn't wired yet).
	var dnsSink mesh.DNSSink
	if *magicDNS {
		if sink, cleanup, err := mesh.StartMagicDNS(logger); err != nil {
			logMagicDNSUnavailable(logger, err)
		} else {
			defer cleanup()
			dnsSink = sink
		}
	}

	// Subnet router / exit node: if advertising CIDRs (or 0.0.0.0/0 via
	// --advertise-exit-node), enable local forwarding + NAT so peers can reach the
	// advertised LAN — or the internet — through this node (best-effort; advertise anyway).
	if len(routes) > 0 {
		if cleanup, err := mesh.EnableSubnetRouter(priv.Public(), routes, logger); err != nil {
			logger.Warn("mesh: subnet-router forwarding not enabled; advertising routes anyway", "err", err)
		} else {
			defer cleanup()
			logger.Info("mesh subnet router enabled", "routes", routes)
		}
	}

	// Exit-node consumer: to full-tunnel through a peer, coord + relay must stay on
	// the physical link (or WireGuard's own transport would loop into the tun).
	if *exitNode != "" {
		dp.SetExitBypassHosts([]string{*coordAddr, *relayAddr})
	}

	conn, err := dialCoord(*coordAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "calabi mesh up: coordinator dial: %v\n", err)
		return 1
	}
	defer conn.Close()

	ctrl := &mesh.Controller{
		Coord:    mesh.NewCoordClient(conn),
		Datapath: dp,
		DNS:      dnsSink,
		Params: mesh.RegisterParams{
			AuthKey:           *authKey,
			NodeKey:           priv.Public(),
			NodePrivate:       priv,
			Name:              *name,
			AdvertiseRoutes:   routes,
			AliasRoutes:       aliased,
			DeviceFingerprint: resolveFingerprint(logger),
		},
		ExitNode: *exitNode,
		Logger:   logger,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logger.Info("mesh up — joining meshnet (Ctrl-C to leave)", "coord", *coordAddr, "relay", *relayAddr)

	if err := ctrl.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, "calabi mesh up: %v\n", err)
		return 1
	}
	return 0
}

func defaultNodeName() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return randomNodeName()
}

// logMagicDNSUnavailable reports a MagicDNS start-up failure at the volume it
// deserves. Both mesh entry points — foreground `mesh up` and the daemon
// runner — go through here so the two can't drift apart.
//
// Off Linux the OS integration simply isn't wired (MESH.6).
// That is the EXPECTED state on Windows and macOS, so warning about it on
// every single start reads as a fault and keeps advertising a feature we no
// longer offer. A failure on a platform that does support it is a different
// thing — there, something actually went wrong, and it stays a warning.
func logMagicDNSUnavailable(logger *slog.Logger, err error) {
	if errors.Is(err, mesh.ErrMagicDNSUnsupported) {
		logger.Debug("mesh: MagicDNS OS integration not wired on this platform; device names won't resolve via the OS", "err", err)
		return
	}
	logger.Warn("mesh: MagicDNS unavailable; device names won't resolve via the OS", "err", err)
}

// meshNodeLabel turns a raw name into a MagicDNS label: lowercase, only
// [a-z0-9-], no leading/trailing "-", at most 63 chars. Anything that doesn't
// survive that becomes a random label instead of a shared constant — a mesh name
// is what peers RESOLVE, so two machines answering to one name is an ambiguous
// lookup, and a fixed fallback guarantees exactly that collision. Pure.
func meshNodeLabel(hostname string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(hostname)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '.' || r == '_' || r == ' ':
			b.WriteByte('-')
		}
	}
	label := strings.Trim(b.String(), "-")
	for strings.Contains(label, "--") {
		label = strings.ReplaceAll(label, "--", "-")
	}
	if len(label) > 63 {
		label = strings.Trim(label[:63], "-")
	}
	if label == "" {
		return randomNodeName()
	}
	return label
}

// randomNodeName is the DEFAULT mesh name: "eq-" (equipment) plus 8 hex chars.
//
// Deliberately not the hostname. A node name is the only identifier that reaches
// PEERS — it is the MagicDNS label in their netmap, while the self-reported
// hostname stays between the node and the coordinator (see Peer in coord.proto).
// Defaulting to the hostname would publish "someones-macbook" to everyone in the
// org, and on a BYOD fleet that is a leak you cannot take back. The console shows
// the hostname next to the name so an admin can still tell the machines apart and
// rename them deliberately.
//
// Falls back to a time-derived suffix if the OS RNG fails, because returning a
// constant here would recreate the very collision this exists to avoid.
func randomNodeName() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("eq-%08x", time.Now().UnixNano()&0xffffffff)
	}
	return "eq-" + hex.EncodeToString(b[:])
}

// meshNodeNameFor picks this machine's mesh name. An explicit --name wins — the
// operator said what to call it, and an operator naming machines is exactly the
// case MagicDNS is for. Otherwise a random label (see randomNodeName).
//
// The --name DEFAULT is never used: it names the CLIENT in the dashboard, where
// "daemon" is merely unhelpful, but as a mesh name it is actively wrong — every
// machine registering as "daemon" makes "daemon.mesh" resolve to whichever one
// you happen to hit (see core/nodename.go).
// It is minted ONCE and persisted: the name is the MagicDNS label peers resolve
// (<name>.mesh), so generating a fresh one on every daemon start broke every
// peer that had been using it and renamed the device in the console on each
// restart. An admin rename is pinned coordinator-side and wins over whatever
// this returns.
func meshNodeNameFor(explicit string) string {
	if explicit != "" {
		return meshNodeLabel(explicit)
	}
	cfg, err := creds.Load()
	if err != nil || cfg == nil {
		// Can't read creds — mint an ephemeral one rather than refuse to join.
		// It churns, which is the old behaviour, but a node on the mesh under a
		// changing name beats a node that isn't on it.
		return randomNodeName()
	}
	if cfg.MeshNodeName != "" {
		return cfg.MeshNodeName
	}
	name := randomNodeName()
	cfg.MeshNodeName = name
	if err := creds.Save(cfg); err != nil {
		// Same posture: use it for this session even though it won't survive.
		return name
	}
	return name
}

// parseServiceSpecs turns --mesh-service / CALABI_MESH_SERVICES into
// declarations. Format per entry:
//
//	name:port                     e.g. db:5432
//	name:proto:port               e.g. dns:udp:53
//	...@target                    e.g. db:5432@192.168.1.50:5432
//
// The optional target is separated by "@" rather than another colon because it
// is itself a host:port — a fourth colon-separated field could not be told apart
// from it. Empty target means 127.0.0.1:<port>.
//
// Entries are comma-separated. A malformed entry is logged and skipped rather
// than failing the daemon: one bad line in a service unit must not keep the
// machine off the mesh (coord applies the same posture to what it receives).
func parseServiceSpecs(logger *slog.Logger, csv string) []meshServiceDecl {
	var out []meshServiceDecl
	for _, raw := range splitCSV(csv) {
		spec, target := raw, ""
		if i := strings.Index(raw, "@"); i >= 0 {
			spec, target = raw[:i], strings.TrimSpace(raw[i+1:])
		}
		parts := strings.Split(spec, ":")
		d := meshServiceDecl{Proto: "tcp", Target: target}
		var portStr string
		switch len(parts) {
		case 2:
			d.Name, portStr = parts[0], parts[1]
		case 3:
			d.Name, d.Proto, portStr = parts[0], parts[1], parts[2]
		default:
			logger.Warn("ignoring --mesh-service entry: want name:port or name:proto:port (optionally @host:port)", "entry", raw)
			continue
		}
		port, err := strconv.Atoi(strings.TrimSpace(portStr))
		if err != nil || port <= 0 || port > 65535 {
			logger.Warn("ignoring --mesh-service entry: bad port", "entry", raw)
			continue
		}
		d.Name = meshproto.NormalizeLabel(d.Name)
		d.Proto = strings.ToLower(strings.TrimSpace(d.Proto))
		d.Port = port
		// The coordinator's own rule, applied here. It SKIPS a name it can't use
		// rather than refusing the registration, so without this check a name
		// with a space in it is declared, dropped on the far side, and never
		// appears in the web console with nothing anywhere explaining it.
		if err := meshproto.ValidateLabel(d.Name); err != nil {
			logger.Warn("ignoring --mesh-service entry: bad name", "entry", raw, "err", err)
			continue
		}
		if err := meshproto.ValidateHostPort(d.Target); err != nil {
			logger.Warn("ignoring --mesh-service entry: bad target", "entry", raw, "err", err)
			continue
		}
		out = append(out, d)
	}
	return out
}

func defaultMeshKeyPath() string {
	// A privileged system service (root LaunchDaemon / LocalSystem) has no
	// usable per-user config dir: a root LaunchDaemon runs with no $HOME, so the
	// os.UserConfigDir() call below errors and we'd fall back to the relative
	// "calabi-mesh.key" — which gets opened against the service's CWD of "/",
	// a read-only filesystem, hence the "read-only file system" data-plane
	// failure. Anchor the key in the machine-wide data dir instead, right next
	// to the service's creds/local-token/pid (see applySystemServiceDataDir and
	// creds.SystemDataDir in the privileged-service plan).
	if os.Getenv("CALABI_SYSTEM_SERVICE") == "1" {
		return filepath.Join(creds.SystemDataDir(), "mesh.key")
	}
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		return "calabi-mesh.key"
	}
	return filepath.Join(dir, "calabi", "mesh.key")
}

// meshConsoleURL is the local daemon console base URL (where /v1/mesh lives).
// meshConsoleCandidates lists the daemon console URLs to try, best first.
//
// Assuming 127.0.0.1:7400 was wrong often enough to be a bug. The daemon binds
// with listenWithFallback, which walks 7400→7419 when the port is taken (that
// is how a second client on one machine gets its own console) — so the address
// the CLI needs is decided at RUNTIME and is not the default. It already gets
// written down: publishConsoleURL records the real bound URL in the daemon's
// data dir. Nothing read it back, so `calabi mesh status` told people their
// daemon was unreachable while it was running one port over.
//
// Two directories, because the daemon's data dir depends on how it was started:
// a user-run daemon uses creds.DataDir(), while one installed as a system
// service keeps its data next to the exe (creds.SetDataDir(exeDir)) — and the
// CLI, run from a shell, resolves the FORMER. Looking in only one place would
// have fixed this for exactly the deployment that does not need it.
//
// An explicit CALABI_STATUS_ADDR is the sole candidate: if someone named an
// address, silently talking to a different daemon is worse than failing.
func meshConsoleCandidates() []string {
	if v := strings.TrimSpace(os.Getenv("CALABI_STATUS_ADDR")); v != "" {
		return []string{"http://" + v}
	}
	var out []string
	seen := map[string]bool{}
	add := func(u string) {
		u = strings.TrimSpace(u)
		if strings.HasPrefix(u, "http://") && !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	if dir, err := creds.DataDir(); err == nil && dir != "" {
		add(readConsoleURLFile(filepath.Join(dir, consoleURLFile)))
	}
	if dir := exeDir(); dir != "" {
		add(readConsoleURLFile(filepath.Join(dir, consoleURLFile)))
	}
	add("http://" + defaultStatusAddr)
	return out
}

// readConsoleURLFile reads a console.url written by a daemon boot, or "".
func readConsoleURLFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// dialMeshConsole GETs path from the first candidate that answers.
//
// "First that ANSWERS" rather than "first that exists": console.url is not
// removed when a daemon stops, so the recorded address can name a daemon that
// is gone while a live one sits on the default port. Trying each in turn costs
// one refused loopback connection and removes a whole class of "it says my
// daemon is down and it isn't".
func dialMeshConsole(path string) (*http.Response, string, error) {
	cands := meshConsoleCandidates()
	var firstErr error
	for _, base := range cands {
		resp, err := http.Get(base + path)
		if err == nil {
			return resp, base, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return nil, strings.Join(cands, ", "), firstErr
}

// meshStatusResp mirrors localweb.MeshStatus.
type meshStatusResp struct {
	Enabled bool   `json:"enabled"`
	Up      bool   `json:"up"`
	Coord   string `json:"coord"`
	Relay   string `json:"relay"`
	Name    string `json:"name"`
	Overlay string `json:"overlay"`
	Peers   []struct {
		PublicKey        string   `json:"public_key"`
		AllowedIPs       []string `json:"allowed_ips"`
		LastHandshakeSec int64    `json:"last_handshake_sec"`
		RxBytes          int64    `json:"rx_bytes"`
		TxBytes          int64    `json:"tx_bytes"`
		Path             string   `json:"path"`
		Endpoint         string   `json:"endpoint"`
		RTTMicros        int64    `json:"rtt_micros"`
		RelayRTTMicros   int64    `json:"relay_rtt_micros"`
	} `json:"peers"`
	// Datapath is the node's own packet accounting. Decoded structurally rather
	// than by embedding localweb's type: this command talks to a daemon that may
	// be a DIFFERENT build (an older service, a newer CLI), so it has to tolerate
	// fields it doesn't know and absent fields it does.
	Datapath struct {
		SockRxPackets  uint64 `json:"sock_rx_packets"`
		SockRxBytes    uint64 `json:"sock_rx_bytes"`
		SockTxPackets  uint64 `json:"sock_tx_packets"`
		SockTxBytes    uint64 `json:"sock_tx_bytes"`
		SockTxErrors   uint64 `json:"sock_tx_errors"`
		SockRxBufBytes int    `json:"sock_rx_buf_bytes"`
		SockTxBufBytes int    `json:"sock_tx_buf_bytes"`
		QueueDepth     int    `json:"queue_depth"`
		QueueCap       int    `json:"queue_cap"`
		QueueDropped   uint64 `json:"queue_dropped"`
		RxDirect       uint64 `json:"rx_direct"`
		RxRelay        uint64 `json:"rx_relay"`
		TxDirect       uint64 `json:"tx_direct"`
		TxRelay        uint64 `json:"tx_relay"`
		TxDirectErrors uint64 `json:"tx_direct_errors"`
		TxRelayErrors  uint64 `json:"tx_relay_errors"`
		TxRelayDropped uint64 `json:"tx_relay_dropped"`
		// Blocked or starved? A shed frame looks identical either way, and the two
		// need opposite investigations — see internal/mesh/derp/sendq.go.
		TxRelayBlockedMs uint64 `json:"tx_relay_blocked_ms"`
		TxRelaySockBuf   uint64 `json:"tx_relay_sockbuf"`
		TxRelayRateBps   uint64 `json:"tx_relay_rate_bps"`
		FilterDropped    uint64 `json:"filter_dropped"`
		Flows            int    `json:"flows"`
	} `json:"datapath"`
}

// runMeshStatus prints the mesh status the local daemon reports on /v1/mesh.
func runMeshStatus(_ []string) int {
	resp, tried, err := dialMeshConsole("/v1/mesh")
	if err != nil {
		fmt.Fprintf(os.Stderr, "calabi mesh status: no daemon answered (%v)\n"+
			"  tried: %s\n"+
			"  is `calabi daemon` running with a `mesh:` block in its config?\n"+
			"  if it is listening somewhere else: CALABI_STATUS_ADDR=host:port calabi mesh status\n",
			err, tried)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "calabi mesh status: %s\n", resp.Status)
		return 1
	}
	var st meshStatusResp
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		fmt.Fprintf(os.Stderr, "calabi mesh status: bad response: %v\n", err)
		return 1
	}
	if !st.Enabled {
		fmt.Println("mesh: not configured (add a `mesh:` block to the daemon config)")
		return 0
	}
	state := "down"
	if st.Up {
		state = "up"
	}
	fmt.Printf("mesh: %s\n", state)
	fmt.Printf("  device:  %s\n", st.Name)
	fmt.Printf("  overlay: %s\n", orDash(st.Overlay))
	fmt.Printf("  coord:   %s\n", st.Coord)
	fmt.Printf("  relay:   %s\n", st.Relay)
	fmt.Printf("  peers:   %d\n", len(st.Peers))
	for _, p := range st.Peers {
		hs := "never"
		if p.LastHandshakeSec > 0 {
			hs = time.Since(time.Unix(p.LastHandshakeSec, 0)).Truncate(time.Second).String() + " ago"
		}
		// Which transport the traffic takes right now: the punched endpoint, or the
		// relay. This is the line that tells you whether hole punching worked.
		path := p.Path
		if path == "" {
			path = "relay"
		}
		if p.Endpoint != "" {
			path += " " + p.Endpoint
		}
		// The RTT is what separates a path that is merely "direct" from one that
		// is any good: two machines on one LAN and the same two hairpinning out
		// through the ISP both read "direct", and differ by a factor of ~20.
		if p.RTTMicros > 0 {
			path += fmt.Sprintf(" %.1fms", float64(p.RTTMicros)/1000)
		} else if p.RelayRTTMicros > 0 {
			// Marked "->relay" because it is NOT the same measurement as the direct
			// case above: that one is end-to-end to the peer, this is one leg to the
			// relay in the middle. Printing it bare would invite comparing a relayed
			// 12ms against a direct 30ms and concluding the relay is faster.
			path += fmt.Sprintf(" ->relay %.1fms", float64(p.RelayRTTMicros)/1000)
		}
		fmt.Printf("    - %s  allowed=%s  path=%s  handshake=%s  rx=%dB tx=%dB\n",
			shortKey(p.PublicKey), strings.Join(p.AllowedIPs, ","), path, hs, p.RxBytes, p.TxBytes)
	}
	printDatapath(st)
	return 0
}

// printDatapath prints the node's own packet accounting — the layer under
// WireGuard's per-peer byte counters, where a loss caused by THIS machine is
// visible.
//
// The lines are ordered as the packet travels, because that is how the numbers
// are read: a drop is found by looking for the step where the count falls. The
// two loss lines are printed unconditionally, zeros included — "dropped 0" is
// the answer that exonerates this node, and hiding it would leave the reader
// unable to tell "nothing dropped" from "this build doesn't count".
func printDatapath(st meshStatusResp) {
	d := st.Datapath
	if d.QueueCap == 0 && d.SockRxPackets == 0 && d.RxRelay == 0 {
		return // a daemon too old to report any of this; say nothing rather than "0"
	}
	fmt.Printf("  datapath:\n")
	fmt.Printf("    socket:  rx %d pkt / %d B    tx %d pkt / %d B    tx-err %d\n",
		d.SockRxPackets, d.SockRxBytes, d.SockTxPackets, d.SockTxBytes, d.SockTxErrors)
	fmt.Printf("    buffers: rx %s  tx %s%s\n",
		humanBytes(d.SockRxBufBytes), humanBytes(d.SockTxBufBytes), bufWarning(d.SockRxBufBytes))
	fmt.Printf("    queue:   %d/%d    dropped %d\n", d.QueueDepth, d.QueueCap, d.QueueDropped)
	fmt.Printf("    transport: rx direct %d / relay %d    tx direct %d / relay %d    tx-err direct %d / relay %d\n",
		d.RxDirect, d.RxRelay, d.TxDirect, d.TxRelay, d.TxDirectErrors, d.TxRelayErrors)
	// Deliberate drops get their own line rather than hiding among the errors:
	// this is the congestion signal a TCP relay would otherwise swallow, and a
	// climbing number here means the relay path is genuinely oversubscribed —
	// which is information, not a fault.
	fmt.Printf("    relay:   dropped-as-stale %d    writer blocked %s%s\n",
		d.TxRelayDropped, humanMillis(d.TxRelayBlockedMs), blockedHint(d.TxRelayBlockedMs))
	// The kernel send buffer behind the relay socket is a queue this node chose
	// the depth of, so it is reported next to the drops for the same reason. It
	// is rendered as TIME as well as bytes because bytes are not what went wrong:
	// 8 MB was a problem only because on that link it was 21 seconds.
	fmt.Printf("    sndbuf:  %s\n", sndbufLine(d.TxRelaySockBuf, d.TxRelayRateBps))
	fmt.Printf("    filter:  dropped %d    flows %d\n", d.FilterDropped, d.Flows)
}

// sndbufLine renders the kernel send-buffer state behind the relay socket.
//
// Three states, and telling them apart is the whole job. This line first
// shipped able to say only two, and it reported a socket PINNED to 64 KB by
// CALABI_MESH_RELAY_SNDBUF as "kernel auto-tuned (no cap applied)" — on a link
// someone was at that moment trying to work out the slowness of. A status line
// that denies the setting doing the damage is worse than no line.
//
// The three are distinguishable from these two numbers alone, without a third
// field, because the adaptive controller CANNOT apply a size before it has a
// rate sample (sndbuf.go: targetLocked needs one). So a size with no rate behind
// it is necessarily a pinned one.
func sndbufLine(bufBytes, rateBps uint64) string {
	switch {
	case bufBytes == 0:
		return "kernel auto-tuned (no cap applied)"
	case rateBps == 0:
		return fmt.Sprintf("%s pinned by %s (not adaptive)", humanBytes(int(bufBytes)), sndbufEnvName)
	default:
		q := time.Duration(float64(bufBytes) * 8 / float64(rateBps) * float64(time.Second))
		return fmt.Sprintf("%s adaptive    %v of queue at the measured %.1f Mbit/s",
			humanBytes(int(bufBytes)), q.Round(time.Millisecond), float64(rateBps)/1e6)
	}
}

// sndbufEnvName is named here rather than imported: the derp package's copy is
// unexported, and a status line naming the wrong variable would send someone
// looking in the wrong place.
const sndbufEnvName = "CALABI_MESH_RELAY_SNDBUF"

// humanMillis renders a cumulative duration counter compactly.
func humanMillis(ms uint64) string {
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}
	return fmt.Sprintf("%.1fs", float64(ms)/1000)
}

// blockedHint says what a large blocked time MEANS, right next to the number.
//
// The counter separates two states every other number reports identically —
// frames offered, frames shed, throughput low — that need opposite
// investigations. Near zero while frames are shed means the writer sat idle and
// the throttle is not this queue at all.
//
// A high value says the writer was waiting on the relay's TCP, and deliberately
// does NOT say why. The first version of this line claimed "the link would not
// take more; the drops beside it are the signal", and on the link that produced
// this counter that reading was wrong: the link carried 18.9 Mbit/s for plain
// iperf3 at the same minute, and the writer was blocked because TCP was in loss
// recovery — while the drops beside it were this queue's own deadline expiring
// mid-recovery. A hint that names one cause invites you to stop looking, which
// is the opposite of what a diagnostic is for.
func blockedHint(ms uint64) string {
	if ms >= 1000 {
		return "   ← waiting on the relay's TCP (a slow link, or loss recovery — check both)"
	}
	return ""
}

// bufWarning flags a receive buffer too small to absorb a burst on a fast path.
// 1 MiB is ~800 full-size packets, about 10ms of a gigabit link — below that, a
// userspace datapath loses packets to nothing but its own scheduling, and those
// losses are invisible here because the kernel discards them before we read.
func bufWarning(rx int) string {
	if rx > 0 && rx < 1<<20 {
		return "   ← small; bursts will be dropped by the kernel before we see them"
	}
	return ""
}

func humanBytes(n int) string {
	switch {
	case n <= 0:
		return "?"
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// runMeshDown asks the local daemon to stop the mesh subsystem (POST
// /v1/mesh/down, local-token gated).
func runMeshDown(_ []string) int {
	// Same resolution as `mesh status` — a daemon that fell back off 7400 has to
	// be stoppable too, or the port scan turns a convenience into a trap.
	var resp *http.Response
	var tried string
	var err error
	for _, base := range meshConsoleCandidates() {
		tried = base
		req, rerr := http.NewRequest(http.MethodPost, base+"/v1/mesh/down", nil)
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "calabi mesh down: %v\n", rerr)
			return 1
		}
		req.Header.Set("X-Local-Token", localTokenFor(base))
		if resp, err = http.DefaultClient.Do(req); err == nil {
			break
		}
	}
	if err != nil || resp == nil {
		fmt.Fprintf(os.Stderr, "calabi mesh down: no daemon answered (last tried %s: %v)\n", tried, err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "calabi mesh down: %s\n", resp.Status)
		return 1
	}
	fmt.Println("mesh: down (restart the daemon, or re-enable in its config, to rejoin)")
	return 0
}

// parseCIDRList parses a comma-separated list of subnet routes. A bare address
// is a host route (192.168.1.22 == 192.168.1.22/32) and an IPv4 route wider than
// a /24 is refused — see mesh.ParseRoute, which is also what the :7400 console
// and the daemon config go through, so the rule has one definition.
func parseCIDRList(csv string) ([]netip.Prefix, error) {
	return mesh.ParseRouteList(csv)
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func shortKey(k string) string {
	if len(k) > 12 {
		return k[:12] + "…"
	}
	return k
}

func printMeshUsage() {
	fmt.Fprintln(os.Stderr, `calabi mesh -- the WireGuard mesh subsystem

Usage:
  calabi mesh up --coord HOST:PORT --relay HOST:PORT --auth-key KEY [--name N] [--key-file PATH]
                 [--advertise-routes CIDR,...] [--advertise-exit-node] [--exit-node NAME|IP]
     Join the meshnet in the FOREGROUND: enroll with the coordinator, bring up a
     WireGuard tun over the relay, apply the netmap. Ctrl-C to leave.
     --advertise-routes / --advertise-exit-node make this node a subnet router /
     exit node; --exit-node routes THIS node's default traffic through a peer.
  calabi mesh status
     Show the mesh status of the running local daemon (reads :7400 /v1/mesh).
  calabi mesh down
     Ask the running local daemon to stop the mesh subsystem.
  calabi mesh relaytest [--relay host:3340] [--seconds N] [--size N] [--rate Mbit]
     Drive ONE LEG of the relay path — this node to the relay and back, through
     the relay's own read and write loops, with no second node, no WireGuard and
     no tun involved. Run it on each end to tell "this leg's network is slow"
     from "the relay's forwarding is slow" from "our datapath is slow"; a
     transfer between two nodes cannot separate those, because it crosses all
     three at once.

Run mesh as a background SERVICE via the local daemon: add a mesh: block
(enabled/coord/relay/auth_key/name) to the daemon config and run
'calabi daemon --local --config tunnels.yaml' (installable with
'calabi daemon install'). status/down talk to that daemon.

Notes:
  - Requires a tun device + privileges (wintun.dll on Windows).`)
}
