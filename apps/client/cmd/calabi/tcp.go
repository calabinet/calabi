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

// runTCP implements `calabi tcp <local-port> [--remote-port N]`.
//
// Wire-protocol-wise this is identical to runHTTP except for the
// ProxyKind (tcp vs http) and how the assigned address is printed.
func runTCP(args []string) int {
	fs := flag.NewFlagSet("tcp", flag.ContinueOnError)
	name := fs.String("name", "tcp", "tunnel name shown in dashboard")
	remotePort := fs.Uint("remote-port", 0, "request a specific edge port (0 = auto-assign from pool)")
	host := fs.String("host", "127.0.0.1", "local host to forward to")
	sec := registerSecurityFlags(fs, false)
	if err := fs.Parse(reorderArgs(args, valueFlagsOf(fs))); err != nil {
		return 2
	}
	secJSON, secErr := sec.buildConfigJSON()
	if secErr != nil {
		fmt.Fprintln(os.Stderr, "calabi tcp:", secErr)
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "calabi tcp: missing <local-port>")
		fs.Usage()
		return 2
	}
	localPort, err := strconv.Atoi(fs.Arg(0))
	if err != nil || localPort <= 0 || localPort > 65535 {
		fmt.Fprintln(os.Stderr, "calabi tcp: invalid <local-port>:", fs.Arg(0))
		return 2
	}
	if *remotePort > 65535 {
		fmt.Fprintln(os.Stderr, "calabi tcp: --remote-port out of range")
		return 2
	}
	localAddr := fmt.Sprintf("%s:%d", *host, localPort)
	if err := validateLocalUpstream(localAddr); err != nil {
		fmt.Fprintln(os.Stderr, "calabi tcp:", err)
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
	edge, code := openOneShotEdge(logger, "tcp")
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
		Type:               proto.ProxyKindTCP,
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
		Type:       "tcp",
		LocalAddr:  localAddr,
		PublicAddr: fmt.Sprintf("tcp://%s:%d", edgeHostForState, assigned.RemotePort),
	})
	defer state.RemoveTunnel(assigned.ProxyID)

	proxies := map[string]session.Tunnel{assigned.ProxyID: tun}
	resolve := func(id string) (session.Tunnel, bool) {
		t, ok := proxies[id]
		return t, ok
	}

	edgeHost := edgeAddr
	// Strip control-port suffix from edgeHost for display purposes.
	if i := lastIndexByte(edgeHost, ':'); i > 0 {
		edgeHost = edgeHost[:i]
	}
	fmt.Printf("\n  tunnel: tcp://%s:%d  ->  %s\n\n",
		edgeHost, assigned.RemotePort, localAddr)
	fmt.Println("  Ctrl-C to quit.")

	if err := cli.Run(ctx, resolve); err != nil {
		logger.Info("session ended", "err", err)
	}
	return 0
}

// lastIndexByte avoids pulling in strings just for this one helper.
func lastIndexByte(s string, c byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == c {
			return i
		}
	}
	return -1
}
