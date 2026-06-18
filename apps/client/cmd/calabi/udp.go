package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/calabi/calabi/apps/client/internal/session"
	"github.com/calabi/calabi/apps/client/internal/status"
	"github.com/calabi/calabi/apps/client/internal/transport"
	proto "github.com/calabi/calabi/pkg/protocol"
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
	sec, secNames := registerSecurityFlags(fs, false)
	if err := fs.Parse(reorderArgs(args, append([]string{"name", "remote-port", "host"}, secNames...))); err != nil {
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
	logger.Info("connecting",
		"server", envOr("CALABI_SERVER", defaultServer),
		"local", localAddr)

	mux, err := transport.Dial(transport.DialOptions{
		Addr:       envOr("CALABI_SERVER", defaultServer),
		Insecure:   envBool("CALABI_INSECURE", defaultInsecure),
		CACertFile: envOr("CALABI_EDGE_CA_FILE", ""),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "calabi: dial:", err)
		return 1
	}

	cli := session.New(logger, mux, resolveToken(), *name)
	cli.SetDeviceID(resolveDeviceID())

	state := status.New(version, envOr("CALABI_SERVER", defaultServer))
	cli.AttachTracker(state)
	startStatusPage(logger, state)

	ctx, cancel := withSignalContext()
	defer cancel()

	if err := cli.Handshake(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "calabi: handshake:", err)
		return 1
	}

	tun := session.Tunnel{
		Name:               *name,
		Type:               proto.ProxyKindUDP,
		LocalAddr:          localAddr,
		RemotePort:         uint32(*remotePort),
		SecurityConfigJSON: secJSON,
	}
	assigned, err := cli.RegisterTunnel(ctx, tun)
	if err != nil {
		fmt.Fprintln(os.Stderr, "calabi: register tunnel:", err)
		return 1
	}

	edgeHostForState := envOr("CALABI_SERVER", defaultServer)
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
