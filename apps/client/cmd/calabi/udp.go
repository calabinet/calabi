package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/calabinet/calabi/apps/client/internal/session"
	"github.com/calabinet/calabi/apps/client/internal/status"
	proto "github.com/calabinet/calabi/pkg/protocol"
)

// runUDP implements `calabi udp <local-port> [--remote-port N]`.
//
// Wire-protocol-wise this mirrors `tcp`: the only differences are
// ProxyKind (udp vs tcp) and how the dispatcher pumps bytes (length-
// prefixed datagrams instead of stream io.Copy). The edge allocates a
// remote UDP port, opens a per-flow yamux stream per visitor, and the
// client side replies via the framed channel.
func runUDP(args []string) int {
	fs := flag.NewFlagSet("udp", flag.ContinueOnError)
	name := fs.String("name", "udp", "tunnel name shown in dashboard")
	remotePort := fs.Uint("remote-port", 0, "request a specific edge port (0 = auto-assign from pool)")
	host := fs.String("host", "127.0.0.1", "local host to forward to")
	sec := registerSecurityFlags(fs, false)
	if err := fs.Parse(reorderArgs(args, valueFlagsOf(fs))); err != nil {
		return 2
	}
	secJSON, secErr := sec.buildConfigJSON()
	if secErr != nil {
		fmt.Fprintln(os.Stderr, "calabi udp:", secErr)
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "calabi udp: missing <local-port>")
		fs.Usage()
		return 2
	}
	localPort, err := strconv.Atoi(fs.Arg(0))
	if err != nil || localPort <= 0 || localPort > 65535 {
		fmt.Fprintln(os.Stderr, "calabi udp: invalid <local-port>:", fs.Arg(0))
		return 2
	}
	if *remotePort > 65535 {
		fmt.Fprintln(os.Stderr, "calabi udp: --remote-port out of range")
		return 2
	}
	localAddr := fmt.Sprintf("%s:%d", *host, localPort)
	if err := validateLocalUpstream(localAddr); err != nil {
		fmt.Fprintln(os.Stderr, "calabi udp:", err)
		return 1
	}

	logger := setupLogger()
	// Make this machine attributable before the tunnel exists: without a
	// device id the row is stored with client_id = 0 and the console can show
	// neither which machine it runs on nor whether that machine is up.
	ensureDeviceRegistered(logger)
	// calabi.net: CALABI_SERVER (or a baked default, if this build has one),
	// else the edge the control plane names — the same picker the daemon uses.
	// Self-hosted: the edge the coordinator this device joined names.
	edge, code := openOneShotEdge(logger, "udp")
	if edge == nil {
		return code
	}
	defer edge.Close()
	edgeAddr := edge.addr

	cli := edge.newSession(logger, *name)

	state := status.New(version, edgeAddr)
	cli.AttachTracker(state)
	startStatusPage(logger, state)

	ctx, cancel := withSignalContext()
	defer cancel()

	if err := cli.Handshake(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "calabi: handshake:", err)
		return 1
	}
	edge.keepFresh(ctx, logger, cli)

	tun := session.Tunnel{
		Name:               *name,
		Type:               proto.ProxyKindUDP,
		LocalAddr:          localAddr,
		RemotePort:         uint32(*remotePort),
		SecurityConfigJSON: secJSON,
	}
	assigned, err := cli.RegisterTunnel(ctx, tun)
	if err != nil {
		printRegisterError(os.Stderr, err)
		return 1
	}
	// What the EDGE did with the policy we sent — not what we assumed it would.
	sec.NoteEdgePolicy(assigned.ClientPolicy)

	edgeHostForState := edgeAddr
	if i := lastIndexByte(edgeHostForState, ':'); i > 0 {
		edgeHostForState = edgeHostForState[:i]
	}
	state.AddTunnel(status.TunnelInfo{
		ProxyID:    assigned.ProxyID,
		Name:       *name,
		Type:       "udp",
		LocalAddr:  localAddr,
		PublicAddr: fmt.Sprintf("udp://%s:%d", edgeHostForState, assigned.RemotePort),
	})
	defer state.RemoveTunnel(assigned.ProxyID)

	proxies := map[string]session.Tunnel{assigned.ProxyID: tun}
	resolve := func(id string) (session.Tunnel, bool) {
		t, ok := proxies[id]
		return t, ok
	}

	fmt.Printf("\n  tunnel: udp://%s:%d  ->  %s\n\n",
		edgeHostForState, assigned.RemotePort, localAddr)
	fmt.Println("  Ctrl-C to quit.")

	if err := cli.Run(ctx, resolve); err != nil {
		logger.Info("session ended", "err", err)
	}
	return 0
}
