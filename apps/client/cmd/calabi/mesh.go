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

// runMesh is the `calabi mesh` command group — the Connect (WireGuard mesh)
// subsystem. Available in BOTH editions (mesh is the open data plane).
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
	relayAddr := fs.String("relay", "", "calabi-derp relay address host:port (this node's DERP home)")
	authKey := fs.String("auth-key", "", "tk_ auth key (platform) or pre-shared key (community)")
	name := fs.String("name", defaultNodeName(), "node name (used for MagicDNS)")
	keyFile := fs.String("key-file", defaultMeshKeyPath(), "path to the node's WireGuard private key (created if absent)")
	advertise := fs.String("advertise-routes", "", "comma-separated CIDRs to advertise as a subnet router (e.g. 192.168.1.0/24)")
	advertiseExit := fs.Bool("advertise-exit-node", false, "advertise this node as an exit node (offer to forward peers' default route to the internet)")
	exitNode := fs.String("exit-node", "", "route this node's default traffic through the named exit-node peer (name or overlay IP)")
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
	dp, err := mesh.NewWGDatapath(priv, *relayAddr, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "calabi mesh up: datapath: %v\n", err)
		return 1
	}
	defer dp.Close()

	// MagicDNS: resolve peer names to overlay IPs. Best-effort — mesh still works
	// without it (e.g. on platforms whose OS integration isn't wired yet).
	var dnsSink mesh.DNSSink
	if sink, cleanup, err := mesh.StartMagicDNS(logger); err != nil {
		logger.Warn("mesh: MagicDNS unavailable; node names won't resolve via the OS", "err", err)
	} else {
		defer cleanup()
		dnsSink = sink
	}

	// Subnet router / exit node: if advertising CIDRs (or 0.0.0.0/0 via
	// --advertise-exit-node), enable local forwarding + NAT so peers can reach the
	// advertised LAN — or the internet — through this node (best-effort; advertise anyway).
	if len(routes) > 0 {
		if cleanup, err := mesh.EnableSubnetRouter(routes); err != nil {
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
			Name:              *name,
			AdvertiseRoutes:   routes,
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
func meshConsoleURL() string {
	return "http://" + envOr("CALABI_STATUS_ADDR", defaultStatusAddr)
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
	} `json:"peers"`
}

// runMeshStatus prints the Connect status the local daemon reports on /v1/mesh.
func runMeshStatus(_ []string) int {
	resp, err := http.Get(meshConsoleURL() + "/v1/mesh")
	if err != nil {
		fmt.Fprintf(os.Stderr, "calabi mesh status: daemon not reachable at %s (%v)\n"+
			"  is `calabi daemon` running with a `mesh:` block in its config?\n", meshConsoleURL(), err)
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
	fmt.Printf("  node:    %s\n", st.Name)
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
		fmt.Printf("    - %s  allowed=%s  path=%s  handshake=%s  rx=%dB tx=%dB\n",
			shortKey(p.PublicKey), strings.Join(p.AllowedIPs, ","), path, hs, p.RxBytes, p.TxBytes)
	}
	return 0
}

// runMeshDown asks the local daemon to stop the mesh subsystem (POST
// /v1/mesh/down, local-token gated).
func runMeshDown(_ []string) int {
	tok, _ := creds.LoadLocalToken()
	req, err := http.NewRequest(http.MethodPost, meshConsoleURL()+"/v1/mesh/down", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "calabi mesh down: %v\n", err)
		return 1
	}
	req.Header.Set("X-Local-Token", tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "calabi mesh down: daemon not reachable at %s (%v)\n", meshConsoleURL(), err)
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

// parseCIDRList parses a comma-separated list of CIDRs (each masked to its
// network). Empty input yields nil.
func parseCIDRList(csv string) ([]netip.Prefix, error) {
	csv = strings.TrimSpace(csv)
	if csv == "" {
		return nil, nil
	}
	var out []netip.Prefix
	for _, s := range strings.Split(csv, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", s, err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
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
	fmt.Fprintln(os.Stderr, `calabi mesh -- Connect (WireGuard mesh) subsystem

Usage:
  calabi mesh up --coord HOST:PORT --relay HOST:PORT --auth-key KEY [--name N] [--key-file PATH]
                 [--advertise-routes CIDR,...] [--advertise-exit-node] [--exit-node NAME|IP]
     Join the meshnet in the FOREGROUND: enroll with the coordinator, bring up a
     WireGuard tun over the calabi-derp relay, apply the netmap. Ctrl-C to leave.
     --advertise-routes / --advertise-exit-node make this node a subnet router /
     exit node; --exit-node routes THIS node's default traffic through a peer.
  calabi mesh status
     Show the Connect status of the running local daemon (reads :7400 /v1/mesh).
  calabi mesh down
     Ask the running local daemon to stop the mesh subsystem.

Run mesh as a background SERVICE via the local daemon: add a mesh: block
(enabled/coord/relay/auth_key/name) to the daemon config and run
'calabi daemon --local --config tunnels.yaml' (installable with
'calabi daemon install'). status/down talk to that daemon.

Notes:
  - Requires a tun device + privileges (wintun.dll on Windows).`)
}
